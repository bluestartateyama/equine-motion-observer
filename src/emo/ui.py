"""Windows local image notebook. All network operations require an opt-in launch."""
import threading
import uuid
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from PIL import ImageTk

from .auth import Loopback, OAuthClient
from .images import LocalImage
from .observation import FEATURES, empty_observation, make_record, validate
from .provider import DispatchLedger, ResponsesProvider
from .storage import CredentialStore, ResultStore, local_root
from .sse import StreamRejected
from .transport import HTTPSClient

# Official SIWC sign-in mark; excluded from the MIT grant (see NOTICE).
CHATGPT_MARK_PNG = 'iVBORw0KGgoAAAANSUhEUgAAABUAAAAVCAIAAAAmdTLBAAADX0lEQVR4nHVUTUgqURQ+c69CqGBBjkRRIKIuJsiYTGjVKlppLlu0CMFtQXtXJmbgwpplCO60IKjIEAxaFEE/JEE/OJaaivagTNGs7D5yQnvm+xZ37h3Oued8557zAfwCxrjliBAS1t/G1G/nWq1GURTLsl1dXefn54+Pj03rOj4/P6EtUD2CyWRKJpN/6sjn8w6HQ61Wj4+Pq9Xqn2atEIvFCCGz2fz29maz2WQyGQBYrVZCSLFYrFQqLy8vh4eHOp1OSKQ951wuNzs7CwASicTtdsfjcafTqVQqRSKRWq32+/2lUqmvr4+iqGYWwk6lUm1tbeVyOYSQ0WjkeT4cDmu1WgAYGRmZnJwUjCORyObmZjMkrn/0en2hUDg7O4tGowDAcVwwGAQAuVzOcVw6nU6lUpFIhGGYoaGhQqEglUq/WQhvE4vFlpeXaZrmeR4APB6P1+udm5urVquEEI1GAwBOpzOTyYRCobu7u6Y/AIyOjpbLZYwxwzA8z2OM7XZ7rVY7ODiwWCzBYPDy8nJqagoAaJoOBALlclnghQUKZrM5kUgAAMuysVgMAFwu18bGRqO6a2trhJBwOKxSqQBgZWXl9vZW6KivyqXTaZqmOzo6stlsT0/P0tKSQqG4urpCCHV2dmKMM5mMz+e7uLg4Pj7u7e1dWFgYGBhgWfarkb7uQOjm5mZ1dRUADAZDNBolhPh8vkb89fV1l8sFADzPsywLAIlEwmQyNeuv0+nK5XIgEOju7gaA6enp6+vr7e1ti8USCoU+Pj7sdjvGmOd5hmEwxq+vr2NjY98tDQBSqfT+/j4UCmWz2cXFRQDQarWEkGq1Oj8/7/V6PR6PEJ+mabfbnUwmRSLRF/2G//Pz8+DgIMMw+/v7qVTq4eGB4zi5XA4AwWCQ4zgAiEajp6enpVLJYDC0ttDu7u7e3p5AeGJiYnh4WMgiHA7zPG80GgEgm83u7OwIg/RP/1IU1d/fXywW/X6/RqMRiURKpdLpdMbjcbfbLZFIAGBmZiaXy7XVCBBY6HS6o6OjUqlUqVSKxSIhxGq1AoBMJrPZbO/v72azGSEkFov/O/wA0Jh2h8ORz+cFIUgmk8KDtQz/P2OMECJ1NP4oFAq9Xv/09HRyckIIEdSpTfCWWxqa11YjfuIvOq+LRfY3kCQAAAAASUVORK5CYII='

LABELS = {'gait': '歩様', 'posture': '姿勢', 'body_appearance': '馬体・体表',
          'hindlimbs': '後肢', 'coordination': '協調性', 'vitality': '活気', 'sweat': '発汗'}

class ObserverApp:
    def __init__(self, root, live=False, data_directory=None):
        self.root = root
        self.live = live
        self.directory = Path(data_directory) if data_directory else local_root()
        self.image = None
        self.origin = 'manual'
        self.metrics = {}
        self.ai_binding = None
        self.busy = False
        self.stop_event = threading.Event()
        self.auth = None
        self.provider = None
        self.subject = tk.StringVar(value='subject-1')
        self.frame = tk.StringVar(value='frame-1')
        self.status = tk.StringVar(value='画像を選択し、見える特徴だけを記録してください。')
        self.review = tk.BooleanVar(value=False)
        self.connection_status = tk.StringVar(value='オフライン：手入力の観察記録を利用できます。')
        root.title('Equine Motion Observer')
        root.geometry('1220x830')
        root.minsize(1000, 720)
        outer = ttk.Frame(root, padding=16)
        outer.pack(fill='both', expand=True)
        ttk.Label(outer, text='Equine Motion Observer', font=('Segoe UI', 22, 'bold')).pack(anchor='w')
        ttk.Label(outer, text='画像を見て、観察できる特徴と根拠を残すローカル研究ノート').pack(anchor='w', pady=(0, 12))
        tabs = ttk.Notebook(outer)
        tabs.pack(fill='both', expand=True)
        editor, connection = ttk.Frame(tabs, padding=12), ttk.Frame(tabs, padding=16)
        tabs.add(editor, text='画像と観察記録')
        tabs.add(connection, text='ChatGPT接続')
        controls = ttk.Frame(editor)
        controls.pack(fill='x', pady=(0, 10))
        ttk.Button(controls, text='JPEG / PNGを選択', command=self.choose_image).pack(side='left')
        ttk.Label(controls, text='  対象ID').pack(side='left')
        ttk.Entry(controls, textvariable=self.subject, width=22).pack(side='left', padx=5)
        ttk.Label(controls, text='画像ID').pack(side='left')
        ttk.Entry(controls, textvariable=self.frame, width=18).pack(side='left', padx=5)
        body = ttk.Panedwindow(editor, orient='horizontal')
        body.pack(fill='both', expand=True)
        left, right = ttk.Frame(body), ttk.Frame(body)
        body.add(left, weight=1)
        body.add(right, weight=2)
        self.preview = ttk.Label(left, text='画像のプレビュー', anchor='center')
        self.preview.pack(fill='both', expand=True)
        self.image_info = tk.StringVar(value='画像未選択')
        ttk.Label(left, textvariable=self.image_info, wraplength=360).pack(fill='x', pady=10)
        ttk.Label(left, text='表示用の縮小は原画像に影響しません。\n単一画像で歩行の動きを確定できない場合は「unobservable」を選びます。',
                  wraplength=350).pack(fill='x')
        headings = ('特徴', '状態', '説明', '確信度 0–1', '不明の理由 / 観察根拠')
        for col, label in enumerate(headings):
            ttk.Label(right, text=label).grid(row=0, column=col, sticky='w', padx=3, pady=5)
        self.fields = {}
        for row, key in enumerate(FEATURES, 1):
            status = tk.StringVar(value='unobservable')
            description, confidence, note = tk.StringVar(), tk.StringVar(), tk.StringVar(value='この画像では確認できない')
            self.fields[key] = status, description, confidence, note
            ttk.Label(right, text=LABELS[key]).grid(row=row, column=0, sticky='w', padx=3, pady=12)
            ttk.Combobox(right, textvariable=status, values=('observed', 'unknown', 'unobservable'),
                         width=13, state='readonly').grid(row=row, column=1, padx=3)
            ttk.Entry(right, textvariable=description, width=21).grid(row=row, column=2, sticky='ew', padx=3)
            ttk.Entry(right, textvariable=confidence, width=8).grid(row=row, column=3, padx=3)
            ttk.Entry(right, textvariable=note, width=28).grid(row=row, column=4, sticky='ew', padx=3)
        right.columnconfigure(2, weight=1)
        right.columnconfigure(4, weight=2)
        ttk.Label(right, text='observed：説明と視覚的根拠が必要。\nunknown / unobservable：説明・確信度は空欄（null）、理由を記入。',
                  wraplength=620).grid(row=8, column=0, columnspan=5, sticky='w', pady=12)
        actions = ttk.Frame(editor)
        actions.pack(fill='x', pady=10)
        ttk.Checkbutton(actions, text='AI観察の画像・根拠を人が確認済み', variable=self.review).pack(side='left')
        self.save_button = ttk.Button(actions, text='観察をJSON保存', command=self.save)
        self.save_button.pack(side='right')
        self.ai_button = ttk.Button(actions, text='解析開始', command=self.observe,
                                   state='normal' if live else 'disabled')
        self.ai_button.pack(side='right', padx=10)
        self.stop_button = ttk.Button(actions, text='手動停止', command=self.stop_observation, state='disabled')
        self.stop_button.pack(side='right')
        ttk.Label(editor, text='Model: gpt-6.1-sol — Using ChatGPT plan（解析時）').pack(anchor='w')
        ttk.Button(editor, text='Manage usage', command=self.manage_usage).pack(anchor='w')
        ttk.Label(editor, textvariable=self.status, wraplength=1100).pack(fill='x')
        self._connection_panel(connection)
        if live:
            self.connection_status.set('接続を有効にした起動です。ログイン・送信は各操作の確認後に実行します。')

    def _connection_panel(self, panel):
        ttk.Label(panel, text='Continue with ChatGPT', font=('Segoe UI', 16, 'bold')).pack(anchor='w')
        ttk.Label(panel, text='手入力はログイン不要です。接続時はOpenAIの認可画面で本人が許可します。\n'
            'このアプリ専用の認証を使用し、他アプリの認証情報は読み込みません。', wraplength=1000).pack(anchor='w', pady=12)
        self.account = tk.StringVar(value='新しいアカウント / Workspace')
        self.account_ids = {}
        self.account_box = ttk.Combobox(panel, textvariable=self.account,
            values=(self.account.get(),), width=60, state='readonly')
        self.account_box.pack(anchor='w', pady=8)
        self.account_box.bind('<<ComboboxSelected>>', self.select_account)
        self.signin_mark = tk.PhotoImage(data=CHATGPT_MARK_PNG)
        self.login_button = tk.Button(panel, text='Continue with ChatGPT', command=self.login,
                                      image=self.signin_mark, compound='left', bg='black', fg='white',
                                      activebackground='black', activeforeground='white', padx=14, pady=10,
                                      font=('Segoe UI', 11), borderwidth=0,
                                      state='normal' if self.live else 'disabled')
        self.login_button.pack(anchor='w', pady=8)
        self.refresh_button = ttk.Button(panel, text='セッション更新（自動更新なし）', command=self.renew,
                                        state='normal' if self.live else 'disabled')
        self.refresh_button.pack(anchor='w', pady=8)
        self.logout_button = ttk.Button(panel, text='ログアウト・セッション失効を試みる', command=self.logout,
                                       state='normal' if self.live else 'disabled')
        self.logout_button.pack(anchor='w', pady=8)
        ttk.Button(panel, text='Manage usage — ChatGPTの利用枠を管理', command=self.manage_usage).pack(anchor='w', pady=8)
        ttk.Button(panel, text='ChatGPTの設定でアプリを切断する', command=self.disconnect_help).pack(anchor='w', pady=8)
        self.plan_allowed = tk.BooleanVar(value=False)
        self.credits_off = tk.BooleanVar(value=False)
        self.purchase_off = tk.BooleanVar(value=False)
        self.rights = tk.BooleanVar(value=False)
        self.effort = tk.StringVar(value='medium')
        for title, variable in (
            ('選択したWorkspaceでプラン利用許可とアプリ別上限を本人が確認済み', self.plan_allowed),
            ('ChatGPT設定で、このアプリのCredits使用をOFFと確認済み', self.credits_off),
            ('Credits自動購入をOFFと確認済み', self.purchase_off),
            ('選択画像について外部AI送信の権限を確認済み', self.rights)):
            ttk.Checkbutton(panel, text=title, variable=variable).pack(anchor='w', pady=4)
        ttk.Label(panel, text='思考の強さ').pack(anchor='w', pady=(12, 4))
        ttk.Combobox(panel, textvariable=self.effort, values=('medium', 'high'), state='readonly', width=12).pack(anchor='w')
        ttk.Label(panel, text='Credits使用と自動購入は別設定です。チェックは本人の確認記録であり、サーバー設定を変更しません。\n'
            'ログアウト後も登録は残ります。アプリとの接続解除はChatGPTの設定で行います。',
                  wraplength=1000).pack(anchor='w', pady=16)
        ttk.Label(panel, textvariable=self.connection_status, wraplength=1000).pack(anchor='w')

    def choose_image(self):
        path = filedialog.askopenfilename(filetypes=[('JPEG / PNG', '*.jpg *.jpeg *.png')])
        if path:
            try:
                self.load_image(path)
            except Exception:
                messagebox.showerror('読み込み不可', '画像形式、サイズ、画像IDを確認してください。')

    def load_image(self, path):
        self.image = LocalImage.load(path, self.frame.get())
        self.photo = ImageTk.PhotoImage(self.image.preview((370, 420)))
        self.preview.configure(image=self.photo, text='')
        self.image_info.set(f'{self.image.name}\n{self.image.width} × {self.image.height} / {self.image.format}\nSHA-256: {self.image.sha256}')
        self.populate(empty_observation(self.subject.get()))
        self.origin, self.metrics, self.ai_binding = 'manual', {}, None
        self.review.set(False)
        self.status.set('画像を読み込みました。確認できない特徴はnullのまま保存できます。')

    def populate(self, observation):
        for key, feature in observation['features'].items():
            status, description, confidence, note = self.fields[key]
            status.set(feature['status'])
            description.set(feature['description'] or '')
            confidence.set('' if feature['confidence'] is None else str(feature['confidence']))
            evidence = [e['description'] for e in observation['evidence'] if e['feature'] == key]
            note.set('; '.join(evidence) if evidence else feature['reason'] or '')

    def snapshot(self):
        if self.image is None:
            raise ValueError('Image required')
        if self.frame.get() != self.image.frame_id:
            raise ValueError('画像IDを変更した場合は画像を選び直してください。')
        observation = empty_observation(self.subject.get())
        for key, fields in self.fields.items():
            status, description, confidence, note = (v.get().strip() for v in fields)
            value = {'description': description or None, 'confidence': float(confidence) if confidence else None,
                     'status': status, 'reason': None if status == 'observed' else note or None}
            observation['features'][key] = value
            if status == 'observed':
                observation['evidence'].append({'feature': key, 'image_index': 0,
                    'frame_id': self.image.frame_id, 'sha256': self.image.sha256, 'description': note})
        return validate(observation, self.image, self.subject.get())

    def save_record(self):
        observation = self.snapshot()
        if self.origin == 'siwc':
            if self.ai_binding != (self.subject.get(), self.image.sha256) or not self.review.get():
                raise ValueError('AI観察の対象と画像を確認してください。')
        record = make_record(observation, self.image, self.origin, self.metrics)
        if self.origin == 'siwc':
            record['human_review'] = 'reviewed_by_user'
        return ResultStore(self.directory / 'observations').save(record)

    def save(self):
        try:
            path = self.save_record()
            self.status.set('保存しました：' + str(path))
        except (ValueError, OSError):
            messagebox.showerror('保存不可', '対象ID、各特徴の状態・根拠・null項目、画像ID、人の確認を点検してください。')

    def ensure_connection(self):
        if not self.live:
            raise ValueError('Offline launch')
        if self.auth is None:
            transport = HTTPSClient(enabled=True)
            self.auth = OAuthClient(CredentialStore(self.directory / 'auth'), transport)
            self.provider = ResponsesProvider(transport, DispatchLedger(self.directory / 'dispatch'))

    def run_worker(self, work, done, stoppable=False):
        if self.busy:
            return
        self.busy = True
        self.stop_event.clear()
        self.stop_button.configure(state='normal' if stoppable else 'disabled')
        for button in (self.login_button, self.refresh_button, self.logout_button, self.ai_button, self.save_button):
            button.configure(state='disabled')
        def finish(value, error):
            self.busy = False
            self.stop_button.configure(state='disabled')
            for button in (self.login_button, self.refresh_button, self.logout_button, self.ai_button):
                button.configure(state='normal' if self.live else 'disabled')
            self.save_button.configure(state='normal')
            if error or (stoppable and self.stop_event.is_set()):
                if self.auth:
                    self.update_accounts()
                self.connection_status.set('操作は完了しませんでした。自動再送は行いません。利用枠はManage usageで確認できます。'
                    '認証未完了の登録がある場合は、その登録を選択して認可をやり直してください。')
                self.status.set('停止：' + (error or 'local_stop') + '。未検証応答は保存しません。自動再送はありません。')
            else:
                done(value)
        def worker():
            try:
                value = work()
                self.root.after(0, finish, value, None)
            except StreamRejected as error:
                self.root.after(0, finish, None, error.state)
            except Exception:
                self.root.after(0, finish, None, 'operation_failed')
        threading.Thread(target=worker, daemon=True).start()

    def stop_observation(self):
        if not self.busy or str(self.stop_button['state']) == 'disabled':
            return
        self.stop_event.set()
        self.stop_button.configure(state='disabled')
        self.status.set('ローカル受信を停止します。サーバーの実行停止は保証できません。再送しません。')
        if self.provider:
            threading.Thread(target=self.provider.transport.stop_receiving, daemon=True).start()

    def stream_progress(self, stage):
        labels = {'dispatch_started': '送信開始', 'first_sse_event': 'SSE受信開始',
                  'first_text': '観察テキスト受信中', 'response_completed': 'サーバー完了・検証中',
                  'validation_completed': 'ローカル検証完了'}
        self.root.after(0, self.status.set, labels.get(stage, '観察中'))

    def update_accounts(self):
        self.account_ids = {label: rid for rid, label in self.auth.accounts()}
        self.account_box.configure(values=('新しいアカウント / Workspace', *self.account_ids))

    def select_account(self, *_):
        if self.busy or not self.auth:
            return
        rid = self.account_ids.get(self.account.get())
        if rid:
            self.auth.select(rid)
            self.provider.available = False
            self.connection_status.set('選択中：' + self.account.get())

    def login(self):
        if not self.live or self.busy:
            return
        if not messagebox.askokcancel('ChatGPT接続', '公式の認可画面を開きます。利用条件とアプリの権限を本人が確認して許可してください。\n'
            '本人識別情報と、このアプリのTokenをWindowsのローカル保護領域に保存します。'
            '解析画像は、この操作では送信しません。保存と削除の詳細は同梱のPRIVACY.mdをご確認ください。'):
            return
        self.ensure_connection()
        rid = self.account_ids.get(self.account.get())
        def work():
            callback = Loopback()
            try:
                pending = self.auth.prepare(callback.uri, rid)
                callback.pending = pending
                if not webbrowser.open(pending.url()):
                    raise ValueError('Browser unavailable')
                code, issued = callback.wait()
                return self.auth.complete(pending, code, issued)
            finally:
                callback.close()
        def done(rid):
            welcome_path = self.directory / 'usage-welcome.json'
            from .storage import atomic_write
            from .observation import strict_json
            try:
                welcomed = strict_json(welcome_path.read_text('utf-8')) if welcome_path.exists() else []
            except ValueError:
                welcomed = []
            if rid not in welcomed:
                messagebox.showinfo('ChatGPTプランを使用します', 'このアプリの対象AI操作はChatGPTのプラン利用枠を使います。'
                    '利用枠とCredits設定はChatGPT設定で管理できます。アプリからの追加請求はありません。')
                import json
                atomic_write(welcome_path, json.dumps([*welcomed, rid]).encode('utf-8'))
            self.update_accounts()
            self.account.set(next(label for label, key in self.account_ids.items() if key == rid))
            self.connection_status.set('認証済み：' + self.account.get() + '。モデル利用可否は送信前に確認します。')
        self.run_worker(work, done)

    def renew(self):
        if not self.live or self.busy:
            return
        self.ensure_connection()
        rid = self.account_ids.get(self.account.get())
        if rid and messagebox.askokcancel('セッション更新', 'このアプリの正式OAuthセッションを1回だけ更新します。'):
            self.run_worker(lambda: self.auth.refresh(rid), lambda _: self.connection_status.set('セッションを更新しました。'))

    def logout(self):
        if not self.live or self.busy:
            return
        self.ensure_connection()
        rid = self.account_ids.get(self.account.get())
        if rid:
            def done(state):
                self.provider.available = False
                self.connection_status.set('ローカル認証を消去しました。' +
                    ('サーバーの失効を確認しました。' if state.endswith('remote_revoked') else
                     'サーバーの失効は未確認です。ChatGPT設定でアプリを切断できます。'))
            self.run_worker(lambda: self.auth.logout(rid), done)

    def disconnect_help(self):
        messagebox.showinfo('接続解除', 'ChatGPT → 設定 → セキュリティとログイン / Sign in with ChatGPTから、このアプリを切断してください。\n'
                            'ローカルのログアウトと、アプリ登録の解除は別の操作です。')

    def manage_usage(self):
        if self.live:
            webbrowser.open('https://chatgpt.com/settings/usage')
        else:
            messagebox.showinfo('利用枠の管理', 'ChatGPT → 設定 → Usageで、アプリ別上限・Credits使用・自動購入を確認できます。')

    def observe(self):
        if not self.live or self.busy or self.image is None:
            return
        if not all(v.get() for v in (self.plan_allowed, self.credits_off, self.purchase_off, self.rights)):
            messagebox.showinfo('送信前の確認', '接続タブで利用許可・上限・Credits・自動購入・画像送信権限を確認してください。')
            return
        image, subject, effort = self.image, self.subject.get(), self.effort.get()
        if self.frame.get() != image.frame_id:
            messagebox.showinfo('画像ID', '画像IDを変更した場合は画像を選び直してください。')
            return
        if not messagebox.askokcancel('画像を外部AIへ送信', f'{image.name}\n{image.width} × {image.height}\nSHA-256: {image.sha256}\n'
            f'対象ID：{subject}\n選択画像をOpenAIへ1回送信します。通信完了不明でも自動再送しません。'):
            return
        self.ensure_connection()
        self.connection_status.set('Using ChatGPT plan — ' + self.account.get() + ' / ' + effort)
        rid = self.account_ids.get(self.account.get())
        def work():
            access = self.auth.access(rid)
            self.provider.discover(access)
            return self.provider.observe('observation-' + str(uuid.uuid4()), access, image, subject, effort,
                                         progress=self.stream_progress, cancel=self.stop_event)
        def done(value):
            if self.image is not image or self.subject.get() != subject:
                self.status.set('観察中に対象が変更されました。応答は採用しません。')
                return
            observation, self.metrics = value
            self.populate(observation)
            self.origin = 'siwc'
            self.ai_binding = (subject, image.sha256)
            self.review.set(False)
            self.status.set('AI観察を取得しました。画像と根拠を人が確認してから保存してください。')
        self.run_worker(work, done, stoppable=True)

def launch(live=False):
    root = tk.Tk()
    ObserverApp(root, live=live)
    root.mainloop()
