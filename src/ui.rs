use appcore::viewkit::components::Form as NativeForm;
use appcore::viewkit::{
    event::{EventContext, EventResult, ViewEvent},
    platform::Key,
    view::{Constraints, MeasureContext, PaintContext},
};
use appcore::{
    keychain::{Application, Error, Item, ItemId, Keychain, Secret, Status},
    prelude::*,
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
    sync::mpsc::{self, Receiver, TryRecvError},
    time::{Duration, Instant},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Action {
    Refresh,
    Lock,
    New,
    Select(usize),
    Cancel,
    Submit,
    Reveal,
    Hide,
    Delete,
    Grant(usize),
    Revoke(usize),
    ChangePassword,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Form {
    Main,
    AwaitingLogin,
    Initialize,
    Unlock,
    New,
    Reveal,
    Delete,
    Grant(usize),
    Revoke(usize),
    ChangePassword,
}
struct Snapshot {
    status: Status,
    items: Vec<Item>,
    apps: Vec<Application>,
    revealed: Option<Secret>,
}
enum Job {
    Refresh,
    Lock,
    Initialize(Secret, u64),
    Unlock(Secret, u64),
    Put(String, String, String, Secret),
    Reveal(ItemId, Secret),
    Delete(ItemId, Secret),
    Grant(ItemId, Application, Secret, bool),
    ChangePassword(Secret, Secret),
}
fn execute(job: Job, epoch: u64) -> Result<Snapshot, Error> {
    let k = Keychain::connect()?;
    let manager = k.manager().at_epoch(epoch);
    let mut revealed = None;
    match job {
        Job::Refresh => {}
        Job::Lock => manager.lock()?,
        Job::Initialize(p, epoch) => manager.initialize_at_epoch(p, epoch)?,
        Job::Unlock(p, epoch) => manager.unlock_at_epoch(p, epoch)?,
        Job::Put(service, account, label, secret) => {
            k.put(&service, &account, &label, secret)?;
        }
        Job::Reveal(id, p) => revealed = Some(manager.reveal(id, p)?),
        Job::Delete(id, p) => manager.delete(id, p)?,
        Job::Grant(id, a, p, revoke) => {
            if revoke {
                manager.revoke(id, a, p)?;
            } else {
                manager.grant(id, a, p)?;
            }
        }
        Job::ChangePassword(old, new) => manager.change_password(old, new)?,
    }
    let status = k.status()?;
    let (items, apps) = if status.unlocked {
        (manager.items()?, manager.applications()?)
    } else {
        (vec![], vec![])
    };
    Ok(Snapshot {
        status,
        items,
        apps,
        revealed,
    })
}
struct Field {
    state: TextFieldInteractionState,
    view: Rc<TextField>,
}
impl Field {
    fn new(placeholder: &str, secure: bool, pending: Rc<Cell<Option<Action>>>) -> Self {
        let state = TextFieldInteractionState::new();
        let view = TextField::with_interaction(state.clone())
            .placeholder(placeholder)
            .secure(secure)
            .on_submit(move || pending.set(Some(Action::Submit)));
        Self {
            state,
            view: Rc::new(view),
        }
    }
    fn secret(&self) -> Secret {
        Secret::new(self.state.take_value().into_bytes())
    }
}
fn use_wipe(value: &mut String) {
    // Minimize the UI-owned temporary copy before it is released.
    use appcore::keychain::Secret;
    let bytes = std::mem::take(value).into_bytes();
    drop(Secret::new(bytes));
}
struct Model {
    status: Option<Status>,
    items: Vec<Item>,
    apps: Vec<Application>,
    selected: Option<ItemId>,
    form: Form,
    error: Option<Error>,
    revealed: Option<Secret>,
    hide_at: Option<Instant>,
    last_refresh: Instant,
}
struct Core {
    model: RefCell<Model>,
    pending: Rc<Cell<Option<Action>>>,
    buttons: RefCell<BTreeMap<Action, ButtonInteractionState>>,
    toolbar: ActionToolbarState<Action>,
    worker: RefCell<Option<Receiver<Result<Snapshot, Error>>>>,
    focused: Cell<bool>,
    exposure_generation: Cell<u64>,
    worker_generation: Cell<u64>,
    query: Field,
    password: Field,
    confirm: Field,
    service: Field,
    account: Field,
    label: Field,
    value: Field,
    scroll: ScrollState,
    detail_scroll: ScrollState,
    grant_picker: RefCell<Picker>,
    form_scroll: ScrollState,
}
#[derive(Clone)]
pub struct KeychainView {
    core: Rc<Core>,
}
#[cfg(test)]
fn r(x: f32, y: f32, w: f32, h: f32) -> Rect {
    Rect::new(x, y, w.max(0.0), h.max(0.0))
}
impl Core {
    fn button(&self, label: &str, a: Action) -> Button {
        let state = self.buttons.borrow_mut().entry(a).or_default().clone();
        let pending = self.pending.clone();
        Button::with_interaction_and_label(state, label)
            .size(ButtonSize::Small)
            .on_click(move || pending.set(Some(a)))
    }
    fn start(&self, job: Job) {
        if self.worker.borrow().is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        *self.worker.borrow_mut() = Some(rx);
        self.worker_generation.set(self.exposure_generation.get());
        let mut m = self.model.borrow_mut();
        m.error = None;
        m.revealed = None;
        m.hide_at = None;
        let epoch = m.status.map_or(0, |s| s.session_epoch);
        drop(m);
        std::thread::spawn(move || {
            let _ = tx.send(execute(job, epoch));
        });
    }
    fn poll(&self) {
        let result = self.worker.borrow().as_ref().map(|rx| rx.try_recv());
        match result {
            Some(Ok(reply)) => {
                self.worker.borrow_mut().take();
                let mut m = self.model.borrow_mut();
                match reply {
                    Ok(mut s) => {
                        if !self.focused.get()
                            || self.worker_generation.get() != self.exposure_generation.get()
                        {
                            // A completion queued before blur must not reveal a
                            // secret, even if focus has returned in the meantime.
                            s.revealed = None;
                        }
                        m.status = Some(s.status);
                        m.items = s.items;
                        m.apps = s.apps;
                        if m.selected
                            .is_none_or(|id| !m.items.iter().any(|i| i.id == id))
                        {
                            m.selected = m.items.first().map(|i| i.id);
                        }
                        m.form = if s.status.login_managed && !s.status.unlocked {
                            if s.status.needs_recovery {
                                Form::Unlock
                            } else {
                                Form::AwaitingLogin
                            }
                        } else if !s.status.initialized {
                            Form::Initialize
                        } else if !s.status.unlocked {
                            Form::Unlock
                        } else {
                            Form::Main
                        };
                        m.hide_at = s
                            .revealed
                            .as_ref()
                            .map(|_| Instant::now() + Duration::from_secs(10));
                        m.revealed = s.revealed;
                    }
                    Err(e) => {
                        m.error = Some(e);
                        if matches!(
                            e,
                            Error::Locked
                                | Error::Denied
                                | Error::Unavailable
                                | Error::Storage
                                | Error::Corrupt
                                | Error::Conflict
                        ) {
                            m.items.clear();
                            m.revealed = None;
                            if matches!(e, Error::Storage | Error::Corrupt | Error::Locked) {
                                m.status = Some(Status {
                                    initialized: true,
                                    unlocked: false,
                                    session_epoch: 0,
                                    login_managed: true,
                                    needs_recovery: false,
                                });
                                m.form = Form::AwaitingLogin;
                            } else {
                                m.status = None;
                            }
                        }
                    }
                }
                m.last_refresh = Instant::now();
                drop(m);
                self.refresh_picker();
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.worker.borrow_mut().take();
                self.model.borrow_mut().error = Some(Error::Unavailable);
            }
            _ => {}
        }
    }
    fn refresh_picker(&self) {
        let m = self.model.borrow();
        let item = m
            .selected
            .and_then(|id| m.items.iter().find(|i| i.id == id));
        let mut picker = Picker::new("Allow Application…");
        if let Some(item) = item {
            for (n, a) in m.apps.iter().enumerate() {
                if *a == item.owner || item.grants.contains(a) {
                    continue;
                }
                let pending = self.pending.clone();
                picker = picker.option(format!("{} [{}]", a.package, signer(a)), move || {
                    pending.set(Some(Action::Grant(n)))
                });
            }
        }
        *self.grant_picker.borrow_mut() = picker;
    }
    fn clear_fields(&self) {
        for f in [
            &self.password,
            &self.confirm,
            &self.service,
            &self.account,
            &self.label,
            &self.value,
        ] {
            f.state.clear();
        }
    }
    fn action(&self, a: Action) {
        if self.worker.borrow().is_some() {
            return;
        }
        match a {
            Action::Refresh => self.start(Job::Refresh),
            Action::Lock => self.start(Job::Lock),
            Action::Hide => {
                let mut m = self.model.borrow_mut();
                m.revealed = None;
                m.hide_at = None;
            }
            Action::Select(n) => {
                let mut m = self.model.borrow_mut();
                if let Some(i) = m.items.get(n) {
                    m.selected = Some(i.id);
                }
                m.revealed = None;
                m.hide_at = None;
                drop(m);
                self.detail_scroll.reset();
                self.refresh_picker();
            }
            Action::Cancel => {
                self.clear_fields();
                self.form_scroll.reset();
                let mut m = self.model.borrow_mut();
                m.form = if m.status.is_some_and(|s| s.login_managed && !s.unlocked) {
                    if m.status.is_some_and(|s| s.needs_recovery) {
                        Form::Unlock
                    } else {
                        Form::AwaitingLogin
                    }
                } else if m.status.is_some_and(|s| s.unlocked) {
                    Form::Main
                } else if m.status.is_some_and(|s| s.initialized) {
                    Form::Unlock
                } else {
                    Form::Initialize
                };
                m.error = None;
                m.revealed = None;
                m.hide_at = None;
            }
            Action::New
            | Action::Reveal
            | Action::Delete
            | Action::Grant(_)
            | Action::Revoke(_)
            | Action::ChangePassword => {
                if a == Action::Reveal
                    && self.model.borrow().status.is_some_and(|s| s.login_managed)
                {
                    let id = self.model.borrow().selected;
                    if let Some(id) = id {
                        self.start(Job::Reveal(id, Secret::new(vec![])));
                    }
                    return;
                }
                self.clear_fields();
                self.form_scroll.reset();
                let mut m = self.model.borrow_mut();
                m.revealed = None;
                m.hide_at = None;
                m.form = match a {
                    Action::New => Form::New,
                    Action::Reveal => Form::Reveal,
                    Action::Delete => Form::Delete,
                    Action::Grant(n) => Form::Grant(n),
                    Action::Revoke(n) => Form::Revoke(n),
                    _ => Form::ChangePassword,
                };
                m.error = None;
            }
            Action::Submit => {
                let m = self.model.borrow();
                let form = m.form;
                let id = m.selected;
                let epoch = m.status.map_or(0, |s| s.session_epoch);
                let login_managed = m.status.is_some_and(|s| s.login_managed);
                let target = match form {
                    Form::Grant(n) => m.apps.get(n).cloned(),
                    Form::Revoke(n) => id
                        .and_then(|id| m.items.iter().find(|i| i.id == id))
                        .and_then(|i| i.grants.get(n))
                        .cloned(),
                    _ => None,
                };
                drop(m);
                let approval_password = || {
                    if login_managed {
                        Secret::new(vec![])
                    } else {
                        self.password.secret()
                    }
                };
                if matches!(form, Form::Initialize | Form::ChangePassword) {
                    let first = if form == Form::Initialize {
                        self.password.state.value()
                    } else {
                        self.value.state.value()
                    };
                    let mut check = self.confirm.state.value();
                    let equal = first == check;
                    let mut first = first;
                    use_wipe(&mut first);
                    use_wipe(&mut check);
                    if !equal {
                        self.model.borrow_mut().error = Some(Error::Invalid);
                        return;
                    }
                }
                let job = match form {
                    Form::Initialize => Job::Initialize(self.password.secret(), epoch),
                    Form::Unlock => Job::Unlock(self.password.secret(), epoch),
                    Form::New => Job::Put(
                        self.service.state.value(),
                        self.account.state.value(),
                        self.label.state.value(),
                        self.value.secret(),
                    ),
                    Form::Reveal => {
                        let Some(id) = id else { return };
                        Job::Reveal(id, approval_password())
                    }
                    Form::Delete => {
                        let Some(id) = id else { return };
                        Job::Delete(id, approval_password())
                    }
                    Form::Grant(_) | Form::Revoke(_) => {
                        let (Some(id), Some(target)) = (id, target) else {
                            return;
                        };
                        Job::Grant(
                            id,
                            target,
                            approval_password(),
                            matches!(form, Form::Revoke(_)),
                        )
                    }
                    Form::ChangePassword => {
                        Job::ChangePassword(self.password.secret(), self.value.secret())
                    }
                    Form::AwaitingLogin => Job::Refresh,
                    Form::Main => return,
                };
                self.clear_fields();
                self.start(job);
            }
        }
    }
}
impl KeychainView {
    pub fn new() -> Self {
        let pending = Rc::new(Cell::new(None));
        let core = Rc::new(Core {
            model: RefCell::new(Model {
                status: None,
                items: vec![],
                apps: vec![],
                selected: None,
                form: Form::Main,
                error: None,
                revealed: None,
                hide_at: None,
                last_refresh: Instant::now(),
            }),
            pending: pending.clone(),
            buttons: RefCell::new(BTreeMap::new()),
            toolbar: ActionToolbarState::new(),
            worker: RefCell::new(None),
            focused: Cell::new(true),
            exposure_generation: Cell::new(0),
            worker_generation: Cell::new(0),
            query: Field::new("Search items", false, pending.clone()),
            password: Field::new("Vault password", true, pending.clone()),
            confirm: Field::new("Enter again", true, pending.clone()),
            service: Field::new("Service name", false, pending.clone()),
            account: Field::new("Account name", false, pending.clone()),
            label: Field::new("Label", false, pending.clone()),
            value: Field::new("Secret", true, pending.clone()),
            scroll: ScrollState::new(),
            detail_scroll: ScrollState::new(),
            grant_picker: RefCell::new(Picker::new("Allow Application…")),
            form_scroll: ScrollState::new(),
        });
        core.start(Job::Refresh);
        Self { core }
    }
    fn toolbar(&self) -> ActionToolbar<Action> {
        let busy = self.core.worker.borrow().is_some();
        let login_managed = self
            .core
            .model
            .borrow()
            .status
            .is_some_and(|status| status.login_managed);
        let mut toolbar = ActionToolbar::new(self.core.toolbar.clone())
            .title("Keychain")
            .trailing(
                Action::New,
                self.core
                    .button("Add Item", Action::New)
                    .leading_symbol(SymbolName::Plus)
                    .enabled(!busy),
            )
            .trailing(
                Action::Refresh,
                self.core
                    .button("Refresh", Action::Refresh)
                    .leading_symbol(SymbolName::Refresh)
                    .enabled(!busy),
            );
        if !login_managed {
            toolbar = toolbar
                .trailing(
                    Action::Lock,
                    self.core.button("Lock", Action::Lock).enabled(!busy),
                )
                .trailing(
                    Action::ChangePassword,
                    self.core
                        .button("Change Password", Action::ChangePassword)
                        .enabled(!busy),
                );
        }
        toolbar
    }
    fn content(&self) -> Box<dyn View> {
        let m = self.core.model.borrow();
        let mut layout = VStack::new()
            .alignment(StackAlignment::Stretch)
            .gap(StackGap::None);
        if m.status.is_none() {
            layout = layout.child(
                ContentArea::pane(
                    VStack::new()
                        .alignment(StackAlignment::Stretch)
                        .gap(StackGap::Medium)
                        .child(Text::styled("Keychain", TextRole::TitleSmall))
                        .child(Text::body(if self.core.worker.borrow().is_some() {
                            "Checking your vault…"
                        } else {
                            "Unable to connect to the keychain service."
                        }))
                        .child(
                            self.core
                                .button("Retry", Action::Refresh)
                                .enabled(self.core.worker.borrow().is_none())
                                .layout()
                                .flex_grow(0.0),
                        ),
                )
                .layout()
                .flex_grow(1.0),
            );
        } else if m.form != Form::Main {
            layout = layout.child(
                FormContents(self.core.clone())
                    .layout()
                    .flex_grow(1.0)
                    .flex_shrink(1.0),
            );
        } else {
            let sidebar = VStack::new()
                .alignment(StackAlignment::Stretch)
                .gap(StackGap::Small)
                .child(
                    Padding::all(Theme::current().spacing.medium)
                        .content(SearchField(self.core.clone())),
                )
                .child(
                    Scroll::new(self.core.scroll.clone())
                        .content(ItemList(self.core.clone()))
                        .layout()
                        .flex_grow(1.0)
                        .flex_shrink(1.0),
                );
            layout = layout.child(Toolbar::new(self.toolbar())).child(
                NavigationSplitView::new(
                    sidebar,
                    Scroll::new(self.core.detail_scroll.clone())
                        .content(Details(self.core.clone())),
                )
                .flexible_sidebar(160.0, 280.0, 340.0)
                .minimum_detail_width(320.0)
                .sidebar_insets(appcore::viewkit::edge_insets::EdgeInsets::ZERO)
                .shows_divider(false)
                .layout()
                .flex_grow(1.0)
                .flex_shrink(1.0),
            );
        }
        if let Some(error) = m.error {
            layout = layout.child(
                Padding::symmetric(
                    Theme::current().spacing.large,
                    Theme::current().spacing.small,
                )
                .content(
                    Text::caption(error_text(error)).color(Theme::current().colors.destructive),
                )
                .layout()
                .flex_shrink(0.0),
            );
        }
        Box::new(Surface::app().content(layout))
    }
    fn form_fields(&self) -> Vec<(&Field, &'static str)> {
        let form = self.core.model.borrow().form;
        match form {
            Form::New => vec![
                (&self.core.label, "Label"),
                (&self.core.service, "Service"),
                (&self.core.account, "Account"),
                (&self.core.value, "Secret"),
            ],
            Form::Initialize => vec![
                (&self.core.password, "Password (at least 12 characters)"),
                (&self.core.confirm, "Confirm password"),
            ],
            Form::ChangePassword => vec![
                (&self.core.password, "Current password"),
                (&self.core.value, "New password (at least 12 characters)"),
                (&self.core.confirm, "Confirm password"),
            ],
            Form::AwaitingLogin => vec![],
            Form::Unlock => vec![(&self.core.password, "Previous vault password")],
            _ if self
                .core
                .model
                .borrow()
                .status
                .is_some_and(|s| s.login_managed) =>
            {
                vec![]
            }
            _ => vec![(&self.core.password, "Vault password")],
        }
    }
    fn form_content(&self, theme: &Theme) -> ContentArea<NativeForm<VStack>> {
        let m = self.core.model.borrow();
        let (title, description, submit) = match m.form {
            Form::AwaitingLogin => (
                "Sign-In Required",
                "Lock the screen and sign in again with your OS password. Your existing data has not been changed.",
                "Refresh",
            ),
            Form::Initialize => (
                "Create Vault",
                "Encrypted on this device. This password is separate from sign-in. If you forget it, the vault cannot be recovered.",
                "Create",
            ),
            Form::Unlock => (
                "Connect Vault to Sign-In",
                "Enter your previous vault password once to migrate or recover it. Afterward, OS sign-in unlocks the vault automatically.",
                "Migrate",
            ),
            Form::New => (
                "Add Item",
                "Keychain owns this item. You can explicitly grant access to other applications.",
                "Save",
            ),
            Form::Reveal => (
                "Reveal Secret",
                "The secret is hidden automatically after 10 seconds or when this window loses focus.",
                "Reveal",
            ),
            Form::Delete => (
                "Delete Item",
                "This item will be permanently removed from the vault. This cannot be undone.",
                "Delete",
            ),
            Form::Grant(_) => (
                "Allow Application Access",
                "Allow the application with the selected signing identity to retrieve this item.",
                "Allow",
            ),
            Form::Revoke(_) => (
                "Revoke Application Access",
                "Deny future access. Values already received by the app cannot be recalled.",
                "Revoke",
            ),
            Form::ChangePassword => (
                "Change Password",
                "The vault will be encrypted again with your new password.",
                "Change",
            ),
            Form::Main => return ContentArea::pane(NativeForm::new(VStack::new())),
        };
        let target = match m.form {
            Form::Grant(n) => m.apps.get(n),
            Form::Revoke(n) => m
                .selected
                .and_then(|id| m.items.iter().find(|i| i.id == id))
                .and_then(|i| i.grants.get(n)),
            _ => None,
        };
        let description = if let Some(a) = target {
            format!(
                "{}\nApplication: {}\nSigning identity: {}",
                description,
                a.package,
                a.signer
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            )
        } else {
            description.to_owned()
        };
        let mut fields = VStack::new()
            .alignment(StackAlignment::Stretch)
            .gap(StackGap::Medium)
            .child(Text::body(description).tone(TextTone::Secondary));
        for (field, label) in self.form_fields() {
            fields = fields.child(
                VStack::new()
                    .alignment(StackAlignment::Stretch)
                    .gap(StackGap::ExtraSmall)
                    .child(field.view.label(label))
                    .child(field.view.clone()),
            );
        }
        let busy = self.core.worker.borrow().is_some();
        let mut actions = HStack::new()
            .alignment(StackAlignment::Center)
            .gap(StackGap::Small)
            .child(Spacer::new());
        if !matches!(m.form, Form::Initialize | Form::Unlock) {
            actions = actions.child(
                self.core
                    .button("Cancel", Action::Cancel)
                    .style(ButtonStyle::Ghost)
                    .enabled(!busy),
            );
        }
        actions = actions.child(
            self.core
                .button(if busy { "Working…" } else { submit }, Action::Submit)
                .style(if m.form == Form::Delete {
                    ButtonStyle::Danger
                } else {
                    ButtonStyle::Accent
                })
                .enabled(!busy),
        );
        let layout = VStack::new()
            .alignment(StackAlignment::Stretch)
            .gap(StackGap::Large)
            .child(
                Text::styled(title, TextRole::TitleSmall)
                    .layout()
                    .flex_shrink(0.0),
            )
            .child(
                Scroll::new(self.core.form_scroll.clone())
                    .content(fields)
                    .layout()
                    .flex_grow(1.0),
            )
            .child(actions.layout().flex_shrink(0.0));
        ContentArea::pane(NativeForm::new(layout)).maximum_width(theme.layout.dialog_width)
    }
}
impl View for KeychainView {
    fn measure(&self, c: Constraints, _: &mut MeasureContext<'_>) -> Size {
        c.constrain(c.maximum)
    }
    fn paint(&self, b: Rect, c: &mut PaintContext<'_>) {
        self.core.poll();
        let now = Instant::now();
        {
            let mut m = self.core.model.borrow_mut();
            if m.hide_at.is_some_and(|t| now >= t) {
                m.revealed = None;
                m.hide_at = None;
            }
            if let Some(t) = m.hide_at {
                c.request_redraw_at(t);
            }
        }
        if self.core.worker.borrow().is_some() {
            c.request_redraw_at(now + Duration::from_millis(32));
        }
        self.content().paint(b, c);
    }

    fn handle_event(&self, b: Rect, event: &ViewEvent, c: &mut EventContext<'_>) -> EventResult {
        if let ViewEvent::FocusChanged { focused } = event {
            self.core.focused.set(*focused);
        }
        if matches!(event, ViewEvent::FocusChanged { focused: false }) {
            self.core
                .exposure_generation
                .set(self.core.exposure_generation.get().wrapping_add(1));
            for field in [&self.core.password, &self.core.confirm, &self.core.value] {
                field.state.clear();
            }
            let mut m = self.core.model.borrow_mut();
            m.revealed = None;
            m.hide_at = None;
            c.request_redraw_in(b);
        }
        if self.core.worker.borrow().is_some() {
            return EventResult::Ignored;
        }

        if let ViewEvent::KeyPressed { key, .. } = event {
            if *key == Key::Escape {
                self.core.action(Action::Cancel);
                c.request_redraw_in(b);
                return EventResult::Consumed;
            }
        }
        let mut result = self.content().handle_event(b, event, c);
        if let Some(a) = self.core.pending.take() {
            self.core.action(a);
            c.request_redraw_in(b);
            result = EventResult::Consumed;
        }
        result
    }
}
struct FormContents(Rc<Core>);
impl View for FormContents {
    fn measure(&self, constraints: Constraints, context: &mut MeasureContext<'_>) -> Size {
        KeychainView {
            core: self.0.clone(),
        }
        .form_content(context.theme)
        .measure(constraints, context)
    }
    fn paint(&self, bounds: Rect, context: &mut PaintContext<'_>) {
        KeychainView {
            core: self.0.clone(),
        }
        .form_content(context.theme)
        .paint(bounds, context);
    }
    fn handle_event(
        &self,
        bounds: Rect,
        event: &ViewEvent,
        context: &mut EventContext<'_>,
    ) -> EventResult {
        KeychainView {
            core: self.0.clone(),
        }
        .form_content(context.theme())
        .handle_event(bounds, event, context)
    }
}

struct Details(Rc<Core>);
impl Details {
    fn content(&self) -> ContentArea<VStack> {
        let m = self.0.model.borrow();
        let mut stack = VStack::new()
            .alignment(StackAlignment::Stretch)
            .gap(StackGap::Medium);
        let Some(item) = m
            .selected
            .and_then(|id| m.items.iter().find(|i| i.id == id))
        else {
            return ContentArea::pane(stack.child(Text::body(
                "Select an item to view its details, or add a new item.",
            )));
        };
        stack = stack.child(Text::styled(&item.label, TextRole::TitleSmall));
        for (label, value) in [
            ("Service", item.service.as_str()),
            ("Account", item.account.as_str()),
            ("Owner", item.owner.package.as_str()),
        ] {
            stack = stack.child(
                VStack::new()
                    .alignment(StackAlignment::Stretch)
                    .gap(StackGap::ExtraSmall)
                    .child(Text::caption(label))
                    .child(Text::body(value)),
            );
        }
        stack = stack
            .child(Text::caption(format!(
                "Signing identity: {} · {}",
                item.owner
                    .signer
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
                origin(item.owner.provenance)
            )))
            .child(
                Text::body(
                    m.revealed
                        .as_ref()
                        .map(|s| {
                            std::str::from_utf8(s.expose())
                                .map(str::to_owned)
                                .unwrap_or_else(|_| {
                                    format!("Binary secret ({} bytes)", s.expose().len())
                                })
                        })
                        .unwrap_or_else(|| "••••••••••••".into()),
                )
                .cache_layout(false),
            )
            .child(
                HStack::new()
                    .gap(StackGap::Small)
                    .child(self.0.button(
                        if m.revealed.is_some() {
                            "Hide"
                        } else {
                            "Reveal"
                        },
                        if m.revealed.is_some() {
                            Action::Hide
                        } else {
                            Action::Reveal
                        },
                    ))
                    .child(
                        self.0
                            .button("Delete", Action::Delete)
                            .style(ButtonStyle::Danger),
                    ),
            )
            .child(Divider::new())
            .child(Text::caption("Allowed Applications"));
        for (n, a) in item.grants.iter().enumerate() {
            stack = stack.child(
                self.0
                    .button(
                        &format!("Revoke access for {} [{}]", a.package, signer(a)),
                        Action::Revoke(n),
                    )
                    .style(ButtonStyle::Ghost),
            );
        }
        stack = stack.child(CachedPicker(self.0.clone()));
        ContentArea::pane(stack)
    }
}
impl View for Details {
    fn measure(&self, c: Constraints, ctx: &mut MeasureContext<'_>) -> Size {
        self.content().measure(c, ctx)
    }
    fn paint(&self, b: Rect, c: &mut PaintContext<'_>) {
        self.content().paint(b, c);
    }
    fn handle_event(&self, b: Rect, e: &ViewEvent, c: &mut EventContext<'_>) -> EventResult {
        self.content().handle_event(b, e, c)
    }
}
struct CachedPicker(Rc<Core>);
impl View for CachedPicker {
    fn measure(&self, c: Constraints, ctx: &mut MeasureContext<'_>) -> Size {
        self.0.grant_picker.borrow().measure(c, ctx)
    }
    fn paint(&self, b: Rect, c: &mut PaintContext<'_>) {
        self.0.grant_picker.borrow().paint(b, c)
    }
    fn handle_event(&self, b: Rect, e: &ViewEvent, c: &mut EventContext<'_>) -> EventResult {
        self.0.grant_picker.borrow().handle_event(b, e, c)
    }
}

fn signer(a: &Application) -> String {
    a.signer[..6].iter().map(|b| format!("{b:02x}")).collect()
}
fn origin(value: u8) -> &'static str {
    match value {
        1 => "Built-in application",
        2 => "Signed application",
        _ => "Development application",
    }
}
fn error_text(e: Error) -> &'static str {
    match e {
        Error::Authentication => {
            "The password is incorrect or the vault could not be authenticated."
        }
        Error::Invalid => {
            "Check your entries. A new password must contain at least 12 characters and match the confirmation."
        }
        Error::Locked => "The vault is locked.",
        Error::Denied => "This operation is not permitted.",
        Error::Unavailable => "Unable to connect to the service.",
        Error::Storage => "The vault could not be saved. Unlock it again before continuing.",
        _ => "The operation could not be completed. Refresh to check the current state.",
    }
}
struct SearchField(Rc<Core>);
impl View for SearchField {
    fn measure(&self, c: Constraints, context: &mut MeasureContext<'_>) -> Size {
        self.0.query.view.measure(c, context)
    }
    fn paint(&self, b: Rect, context: &mut PaintContext<'_>) {
        self.0.query.view.paint(b, context);
    }
    fn handle_event(
        &self,
        b: Rect,
        event: &ViewEvent,
        context: &mut EventContext<'_>,
    ) -> EventResult {
        self.0.query.view.handle_event(b, event, context)
    }
}
struct ItemList(Rc<Core>);
impl ItemList {
    fn content(&self) -> VStack {
        let m = self.0.model.borrow();
        let query = self.0.query.state.value().to_lowercase();
        let entries: Vec<_> = m
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                format!("{} {} {}", item.label, item.service, item.account)
                    .to_lowercase()
                    .contains(&query)
            })
            .collect();
        let mut rows = VStack::new()
            .alignment(StackAlignment::Stretch)
            .gap(StackGap::ExtraSmall);
        for (position, (index, item)) in entries.iter().enumerate() {
            let action = Action::Select(*index);
            let interaction = self
                .0
                .buttons
                .borrow_mut()
                .entry(action)
                .or_default()
                .clone();
            let pending = self.0.pending.clone();
            rows = rows.child(
                ListRow::with_interaction(interaction, &item.label)
                    .subtitle(&item.account)
                    .selected(m.selected == Some(item.id))
                    .adjacent_rows(position > 0, position + 1 < entries.len())
                    .on_select(move || pending.set(Some(action)))
                    .layout()
                    .height(Theme::current().layout.list_row_height)
                    .flex_shrink(0.0),
            );
        }
        if entries.is_empty() {
            rows = rows.child(
                Padding::all(Theme::current().spacing.large).content(Text::caption(
                    if query.is_empty() {
                        "No items in this vault."
                    } else {
                        "No matching items."
                    },
                )),
            );
        }
        rows
    }
}
impl View for ItemList {
    fn measure(&self, c: Constraints, context: &mut MeasureContext<'_>) -> Size {
        self.content().measure(c, context)
    }
    fn paint(&self, b: Rect, context: &mut PaintContext<'_>) {
        self.content().paint(b, context);
    }
    fn handle_event(
        &self,
        b: Rect,
        event: &ViewEvent,
        context: &mut EventContext<'_>,
    ) -> EventResult {
        self.content().handle_event(b, event, context)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use appcore::viewkit::{
        draw_command::{DisplayList, DrawCommand},
        event::ContextMenuRequest,
        platform::PointerButton,
        typography::TextMeasurer,
    };
    fn application(name: &str, n: u8) -> Application {
        Application {
            package: name.into(),
            signer: [n; 32],
            provenance: 1,
        }
    }
    fn fixture() -> KeychainView {
        let v = KeychainView::new();
        v.core.worker.borrow_mut().take();
        let owner = application("org.mochios.mail", 1);
        let other = application("org.mochios.terra", 2);
        let item = Item {
            id: [1; 16],
            owner: owner.clone(),
            service: "google.oauth".into(),
            account: "person@example.test".into(),
            label: "Gmail".into(),
            grants: vec![],
        };
        let (tx, rx) = mpsc::channel();
        tx.send(Ok(Snapshot {
            status: Status {
                session_epoch: 1,
                login_managed: false,
                needs_recovery: false,
                initialized: true,
                unlocked: true,
            },
            items: vec![item],
            apps: vec![owner, other],
            revealed: None,
        }))
        .unwrap();
        *v.core.worker.borrow_mut() = Some(rx);
        v.core.poll();
        v
    }
    fn bounds() -> Rect {
        r(0.0, 0.0, 880.0, 620.0)
    }
    fn paint(v: &KeychainView) -> Vec<AccessibilityNode> {
        let theme = Theme::current();
        let mut text = TextMeasurer::new();
        let mut list = DisplayList::new();
        let mut nodes = vec![];
        v.paint(
            bounds(),
            &mut PaintContext::new(&mut list, &theme, &theme.typography, &mut text)
                .with_accessibility_nodes(&mut nodes),
        );
        nodes
    }
    fn event(v: &KeychainView, e: ViewEvent) -> Option<ContextMenuRequest> {
        let theme = Theme::current();
        let mut text = TextMeasurer::new();
        let mut c = EventContext::new(&theme, &theme.typography, &mut text);
        v.handle_event(bounds(), &e, &mut c);
        c.take_context_menu_request()
    }
    fn form_snapshot(
        v: &KeychainView,
        bounds: Rect,
        theme: &Theme,
    ) -> (DisplayList, Vec<AccessibilityNode>) {
        let mut text = TextMeasurer::new();
        let mut list = DisplayList::new();
        let mut nodes = vec![];
        v.content().paint(
            bounds,
            &mut PaintContext::new(&mut list, theme, &theme.typography, &mut text)
                .with_accessibility_nodes(&mut nodes),
        );
        (list, nodes)
    }

    #[test]
    fn standard_forms_keep_actions_reachable_at_small_sizes_in_both_themes() {
        let v = fixture();
        for theme in [Theme::LIGHT, Theme::DARK] {
            for login_managed in [false, true] {
                for (form, submit) in [
                    (Form::AwaitingLogin, "Refresh"),
                    (Form::Initialize, "Create"),
                    (Form::Unlock, "Migrate"),
                    (Form::New, "Save"),
                    (Form::Reveal, "Reveal"),
                    (Form::Delete, "Delete"),
                    (Form::Grant(1), "Allow"),
                    (Form::Revoke(0), "Revoke"),
                    (Form::ChangePassword, "Change"),
                ] {
                    {
                        let mut m = v.core.model.borrow_mut();
                        m.form = form;
                        m.error = Some(Error::Storage);
                        m.status.as_mut().unwrap().login_managed = login_managed;
                    }
                    for (w, h) in [(320., 240.), (880., 620.)] {
                        let b = r(0., 0., w, h);
                        v.core.form_scroll.reset();
                        let (_, nodes) = form_snapshot(&v, b, &theme);
                        let buttons: Vec<_> = nodes
                            .iter()
                            .filter(|n| n.role == AccessibilityRole::Button)
                            .collect();
                        let submit_frame = buttons
                            .iter()
                            .find(|n| n.label.as_deref() == Some(submit))
                            .unwrap()
                            .bounds;
                        assert_eq!(
                            buttons.len(),
                            if matches!(form, Form::Initialize | Form::Unlock) {
                                1
                            } else {
                                2
                            }
                        );
                        for button in &buttons {
                            let frame = button.bounds;
                            assert!(frame.size.width > 0. && frame.size.height > 0.);
                            assert!(frame.origin.x >= 0. && frame.origin.y >= 0.);
                            assert!(frame.origin.x + frame.size.width <= w + 0.1);
                            assert!(frame.origin.y + frame.size.height <= h + 0.1);
                        }
                        for pair in buttons.windows(2) {
                            assert!(
                                pair[0].bounds.origin.x + pair[0].bounds.size.width
                                    <= pair[1].bounds.origin.x
                            );
                        }
                        for node in nodes
                            .iter()
                            .filter(|n| n.role == AccessibilityRole::TextField)
                        {
                            assert!(node.bounds.size.width > 0.);
                            assert!(
                                node.bounds.origin.x >= 0.
                                    && node.bounds.origin.x + node.bounds.size.width <= w + 0.1
                            );
                        }
                        v.core.form_scroll.set_offset(0., 10000.);
                        let (_, after) = form_snapshot(&v, b, &theme);
                        assert_eq!(
                            after
                                .iter()
                                .find(|n| n.label.as_deref() == Some(submit))
                                .unwrap()
                                .bounds,
                            submit_frame
                        );
                        assert!(v.core.pending.get().is_none());
                        assert!(v.core.worker.borrow().is_none());
                    }
                }
            }
        }
    }

    #[test]
    fn native_form_scroll_preserves_secure_input_and_cancel_still_wipes_it() {
        let v = fixture();
        v.core.action(Action::New);
        v.core.value.state.set_value("fixture-only-secret");
        let b = r(0., 0., 320., 240.);
        let theme = Theme::LIGHT;
        let (list, nodes) = form_snapshot(&v, b, &theme);
        let submit = nodes
            .iter()
            .find(|n| n.role == AccessibilityRole::Button && n.label.as_deref() == Some("Save"))
            .unwrap()
            .bounds;
        let body = list
            .commands()
            .iter()
            .find_map(|c| match c {
                DrawCommand::PushClip { rect }
                    if rect.size.height > 0.
                        && rect.origin.y + rect.size.height <= submit.origin.y =>
                {
                    Some(*rect)
                }
                _ => None,
            })
            .unwrap();
        let mut text = TextMeasurer::new();
        let mut context = EventContext::new(&theme, &theme.typography, &mut text);
        v.handle_event(
            b,
            &ViewEvent::Scroll {
                position: Point::new(body.origin.x + 8., body.origin.y + 8.),
                delta_x: 0.,
                delta_y: 1000.,
            },
            &mut context,
        );
        assert!(v.core.form_scroll.offset_y() > 0.);
        let (list, nodes) = form_snapshot(&v, b, &theme);
        let secret = nodes
            .iter()
            .find(|n| {
                n.role == AccessibilityRole::TextField && n.label.as_deref() == Some("Secret")
            })
            .unwrap();
        assert!(secret.value.is_none());
        assert_eq!(v.core.value.state.value(), "fixture-only-secret");
        assert!(!list.commands().iter().any(|c|matches!(c,DrawCommand::DrawText{command} if command.text.contains("fixture-only-secret"))));
        let cancel = nodes
            .iter()
            .find(|n| n.role == AccessibilityRole::Button && n.label.as_deref() == Some("Cancel"))
            .unwrap()
            .bounds;
        let position = Point::new(
            cancel.origin.x + cancel.size.width / 2.,
            cancel.origin.y + cancel.size.height / 2.,
        );
        for e in [
            ViewEvent::PointerPressed {
                position,
                button: PointerButton::Primary,
            },
            ViewEvent::PointerReleased {
                position,
                button: PointerButton::Primary,
            },
        ] {
            v.handle_event(b, &e, &mut context);
        }
        assert!(v.core.value.state.value().is_empty());
        assert!(v.core.model.borrow().form == Form::Main);
        assert!(v.core.worker.borrow().is_none());
    }

    #[test]
    fn native_grant_picker_survives_paints_and_requires_reauthentication() {
        let v = fixture();
        let nodes = paint(&v);
        let node = nodes
            .iter()
            .find(|n| n.label.as_deref() == Some("Allow Application…"))
            .expect("grant picker");
        let point = Point::new(
            node.bounds.origin.x + node.bounds.size.width / 2.0,
            node.bounds.origin.y + node.bounds.size.height / 2.0,
        );
        event(
            &v,
            ViewEvent::PointerPressed {
                position: point,
                button: PointerButton::Primary,
            },
        );
        let menu = event(
            &v,
            ViewEvent::PointerReleased {
                position: point,
                button: PointerButton::Primary,
            },
        )
        .unwrap();
        paint(&v);
        event(
            &v,
            ViewEvent::ContextMenuResult {
                request_id: menu.request_id,
                command_id: Some(1),
            },
        );
        assert!(matches!(v.core.model.borrow().form, Form::Grant(1)));
        assert!(v.core.worker.borrow().is_none());
        assert!(v.core.password.state.value().is_empty());
        paint(&v);
    }
    #[test]
    fn secret_is_hidden_on_expiry_focus_loss_and_cancel() {
        let v = fixture();
        {
            let mut m = v.core.model.borrow_mut();
            m.revealed = Some(Secret::new(b"display-once".to_vec()));
            m.hide_at = Some(Instant::now() - Duration::from_secs(1));
        }
        paint(&v);
        assert!(v.core.model.borrow().revealed.is_none());
        v.core.model.borrow_mut().revealed = Some(Secret::new(b"display-once".to_vec()));
        event(&v, ViewEvent::FocusChanged { focused: false });
        assert!(v.core.model.borrow().revealed.is_none());
        v.core.password.state.set_value("secret input");
        v.core.action(Action::Cancel);
        assert!(v.core.password.state.value().is_empty());
    }
    #[test]
    fn late_reveal_cannot_restore_secret_after_losing_focus() {
        let v = fixture();
        let (tx, rx) = mpsc::channel();
        *v.core.worker.borrow_mut() = Some(rx);
        v.core.password.state.set_value("private input");
        event(&v, ViewEvent::FocusChanged { focused: false });
        event(&v, ViewEvent::FocusChanged { focused: true });
        tx.send(Ok(Snapshot {
            status: Status {
                session_epoch: 1,
                login_managed: false,
                needs_recovery: false,
                initialized: true,
                unlocked: true,
            },
            items: v.core.model.borrow().items.clone(),
            apps: vec![],
            revealed: Some(Secret::new(b"late secret".to_vec())),
        }))
        .unwrap();
        v.core.poll();
        assert!(v.core.model.borrow().revealed.is_none());
        assert!(v.core.password.state.value().is_empty());
    }
    #[test]
    fn storage_failure_removes_stale_unlocked_state() {
        let v = fixture();
        let (tx, rx) = mpsc::channel();
        tx.send(Err(Error::Storage)).unwrap();
        *v.core.worker.borrow_mut() = Some(rx);
        v.core.poll();
        let m = v.core.model.borrow();
        assert!(m.items.is_empty());
        assert!(!m.status.unwrap().unlocked);
        assert!(m.form == Form::AwaitingLogin);
    }
    #[test]
    fn login_managed_approval_has_no_password_field_and_only_recovery_requests_one() {
        let v = fixture();
        {
            let mut m = v.core.model.borrow_mut();
            let mut s = m.status.unwrap();
            s.login_managed = true;
            m.status = Some(s);
            m.form = Form::Grant(1);
        }
        assert!(v.form_fields().is_empty());
        let nodes = paint(&v);
        assert!(
            !nodes
                .iter()
                .any(|n| n.label.as_deref() == Some("Vault password"))
        );
        let mut text = TextMeasurer::new();
        for (action, _, _) in v.toolbar().into_visible_actions(
            bounds(),
            &mut MeasureContext {
                theme: &Theme::LIGHT,
                typography: &Theme::LIGHT.typography,
                text_measurer: &mut text,
            },
        ) {
            assert!(!matches!(action, Action::Lock | Action::ChangePassword));
        }
        v.core.model.borrow_mut().form = Form::AwaitingLogin;
        assert!(v.form_fields().is_empty());
        v.core.model.borrow_mut().form = Form::Unlock;
        assert_eq!(v.form_fields().len(), 1);
    }
    #[test]
    fn toolbar_controls_do_not_overlap_at_supported_widths() {
        let view = fixture();
        let theme = Theme::LIGHT;
        for width in [320.0, 480.0, 640.0, 880.0, 1200.0] {
            let bounds = r(0.0, 0.0, width, theme.layout.top_bar_height);
            let mut text = TextMeasurer::new();
            let controls = view.toolbar().into_visible_actions(
                bounds,
                &mut MeasureContext {
                    theme: &theme,
                    typography: &theme.typography,
                    text_measurer: &mut text,
                },
            );
            for (index, (_, frame, _)) in controls.iter().enumerate() {
                assert!(frame.origin.x >= 0.0 && frame.origin.x + frame.size.width <= width);
                for (_, other, _) in controls.iter().skip(index + 1) {
                    assert!(frame.intersection(*other).is_none());
                }
            }
        }
    }

    #[test]
    fn filtered_native_row_selects_the_original_item_and_clears_exposed_content() {
        let view = fixture();
        let mut item = view.core.model.borrow().items[0].clone();
        item.id = [2; 16];
        item.label = "Other account".into();
        item.account = "other@example.test".into();
        view.core.model.borrow_mut().items.push(item);
        view.core.query.state.set_value("other");
        let nodes = paint(&view);
        let rows: Vec<_> = nodes
            .iter()
            .filter(|node| node.role == AccessibilityRole::ListItem)
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label.as_deref(), Some("Other account"));
        let frame = rows[0].bounds;
        let position = Point::new(
            frame.origin.x + frame.size.width * 0.5,
            frame.origin.y + frame.size.height * 0.5,
        );
        view.core.model.borrow_mut().revealed = Some(Secret::new(b"test-only-value".to_vec()));
        for e in [
            ViewEvent::PointerPressed {
                position,
                button: PointerButton::Primary,
            },
            ViewEvent::PointerReleased {
                position,
                button: PointerButton::Primary,
            },
        ] {
            event(&view, e);
        }
        let model = view.core.model.borrow();
        assert_eq!(model.selected, Some([2; 16]));
        assert!(model.revealed.is_none());
        assert!(model.hide_at.is_none());
        assert!(view.core.worker.borrow().is_none());
    }

    #[test]
    fn standard_split_corners_expose_chrome_and_rows_follow_activation_state() {
        use appcore::viewkit::draw_command::DrawCommand;
        let view = fixture();
        for mut theme in [Theme::LIGHT, Theme::DARK] {
            theme.motion = theme.motion.reduced();
            for active in [true, false] {
                let mut list = DisplayList::new();
                let mut nodes = Vec::new();
                let mut text = TextMeasurer::new();
                view.paint(
                    bounds(),
                    &mut PaintContext::new(&mut list, &theme, &theme.typography, &mut text)
                        .with_window_active(active)
                        .with_accessibility_nodes(&mut nodes),
                );
                assert!(nodes.iter().any(|n| n.role == AccessibilityRole::Toolbar));
                let (index, pane, radii) = list
                    .commands()
                    .iter()
                    .enumerate()
                    .find_map(|(index, command)| match command {
                        DrawCommand::PushRoundedCornersClip { rect, radii }
                            if rect.origin.x > 0.0
                                && rect.origin.y == theme.layout.top_bar_height =>
                        {
                            Some((index, *rect, *radii))
                        }
                        _ => None,
                    })
                    .expect("the toolbar/sidebar junction must use the standard pane clip");
                assert_eq!(radii, [theme.radius.extra_large, 0.0, 0.0, 0.0]);
                let backdrop =
                    list.commands()[..index]
                        .iter()
                        .rev()
                        .find_map(|command| match command {
                            DrawCommand::FillRect { rect, color } if rect.contains(pane.origin) => {
                                Some(*color)
                            }
                            _ => None,
                        });
                assert_eq!(backdrop, Some(theme.colors.surface_subtle));
                let expected = if active {
                    theme.list.selected_foreground
                } else {
                    theme.list.inactive_selected_foreground
                };
                assert!(list.commands().iter().any(|command| matches!(command,
                    DrawCommand::DrawText { command } if command.text == "Gmail"
                        && command.bounds.origin.x < pane.origin.x && command.color == expected
                )));
            }
        }
    }
}
