// server.js

const express = require('express');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const Redis = require('ioredis');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();

app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// /public を静的配信（logo.png 用）
app.use(express.static(path.join(__dirname, 'public')));

// =============================
// Redis & セッション
// =============================
const redisClient = new Redis(process.env.UPSTASH_REDIS_URL);
const redisStore = new RedisStore({
  client: redisClient,
  prefix: 'sententia:'
});

app.use(
  session({
    store: redisStore,
    secret: process.env.SESSION_SECRET || 'sententia-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());

// =============================
// Supabase
// =============================
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// =============================
// Passport (Google OAuth)
// =============================
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: '/auth/google/callback'
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let { data: user, error } = await supabase
          .from('users')
          .select('*')
          .eq('google_id', profile.id)
          .single();

        if (error && error.code !== 'PGRST116') {
          return done(error);
        }

        if (!user) {
          const email =
            profile.emails && profile.emails[0]
              ? profile.emails[0].value
              : null;

          const baseName =
            profile.displayName ||
            (email ? email.split('@')[0] : 'user_' + Date.now());

          let username = baseName.slice(0, 20);

          let handle =
            '@' + baseName.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
          if (handle.length > 20) handle = handle.slice(0, 20);

          const { data: inserted, error: insertError } = await supabase
            .from('users')
            .insert({
              google_id: profile.id,
              username,
              email,
              handle
            })
            .select()
            .single();

          if (insertError) return done(insertError);
          user = inserted;
        }

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('id', id)
    .single();
  if (error) return done(error);
  done(null, user);
});

// =============================
// 共通ヘルパー
// =============================
function ensureAuthenticated(req, res, next) {
  if (req.user) return next();
  return res.redirect('/login-modal');
}

// ロゴ真ん中＋左右にボタンの共通ヘッダー
function renderHeader(user, opts = {}) {
  const showProfileIcon = opts.showProfileIcon !== false;

  // 左上：プロフィールボタン → 設定ボタン の順に並べる
  let leftHtml = '';
  if (user) {
    const profileButton = showProfileIcon
      ? `
    <button onclick="location.href='/me'"
            class="w-10 h-10 rounded-full flex items-center justify-center bg-blue-100">
      <svg viewBox="0 0 24 24" class="w-6 h-6 text-blue-500" fill="currentColor">
        <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4S8 5.79 8 8s1.79 4 4 4zm0 2c-3.33 0-6 2.24-6 5v1h12v-1c0-2.76-2.67-5-6-5z"/>
      </svg>
    </button>
    `
      : '';

    const settingsButton = `
    <button onclick="location.href='/settings'"
            class="w-10 h-10 rounded-full border bg-white flex items-center justify-center hover:bg-gray-50">
      <svg viewBox="0 0 24 24" class="w-6 h-6 text-gray-600" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="3"></circle>
        <path d="
          M19.4 12
          a7.4 7.4 0 0 0-.1-1
          l2-1.6
          a0.7 0.7 0 0 0 .1-0.9
          l-1.9-3.3
          a0.7 0.7 0 0 0-.8-0.3
          l-2.3.9
          a7.4 7.4 0 0 0-1.7-1
          l-.3-2.4
          a0.7 0.7 0 0 0-.7-0.6
          h-3.8
          a0.7 0.7 0 0 0-.7.6
          l-.3 2.4
          a7.4 7.4 0 0 0-1.7 1
          l-2.3-.9
          a0.7 0.7 0 0 0-.8.3
          l-1.9 3.3
          a0.7 0.7 0 0 0 .1.9
          l2 1.6
          a7.4 7.4 0 0 0 0 2
          l-2 1.6
          a0.7 0.7 0 0 0-.1.9
          l1.9 3.3
          a0.7 0.7 0 0 0 .8.3
          l2.3-.9
          a7.4 7.4 0 0 0 1.7 1
          l.3 2.4
          a0.7 0.7 0 0 0 .7.6
          h3.8
          a0.7 0.7 0 0 0 .7-.6
          l.3-2.4
          a7.4 7.4 0 0 0 1.7-1
          l2.3.9
          a0.7 0.7 0 0 0 .8-.3
          l1.9-3.3
          a0.7 0.7 0 0 0-.1-.9
          l-2-1.6
          a7.4 7.4 0 0 0 .1-1
        "></path>
      </svg>
    </button>
    `;

    leftHtml = `
  <div class="absolute left-4 top-3 flex items-center gap-2">
    ${profileButton}
    ${settingsButton}
  </div>
  `;
  }

  // 右上：Log in / Log out
  const rightHtml = user
    ? `
  <div class="absolute right-4 top-3 flex items-center gap-3">
    <form action="/logout" method="POST">
      <button type="submit"
              class="bg-black text-white px-5 py-2 rounded-lg font-medium hover:bg-gray-800">
        Log out
      </button>
    </form>
  </div>
  `
    : `
  <div class="absolute right-4 top-3 flex items-center gap-3">
    <button onclick="location.href='/login-modal'"
            class="bg-black text-white px-5 py-2 rounded-lg font-medium hover:bg-gray-800">
      Log in
    </button>
  </div>
  `;

  // ロゴ（中央）
  return `
<div class="fixed top-0 left-0 right-0 z-40 pt-0 flex justify-center">
  <button onclick="location.href='/'" class="flex items-center -mt-3">
    <img src="/logo.png" alt="sententia" class="h-28 w-[800px] object-contain">
  </button>

  ${leftHtml}
  ${rightHtml}
</div>
`;
}

// =============================
// OAuth ルート
// =============================
app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login-modal' }),
  (req, res) => res.redirect('/')
);

// =============================
// ログインモーダル
// =============================
app.get('/login-modal', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>Login - sententia</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center relative">
  <div class="absolute top-2 left-1/2 -translate-x-1/2">
    <button onclick="location.href='/'" class="flex items-center">
      <img src="/logo.png" alt="sententia" class="h-24 w-[800px] object-contain">
    </button>
  </div>

  <div class="bg-white rounded-3xl shadow-2xl p-8 w-full max-w-lg relative mt-20">
    <button onclick="location.href='/'"
            class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-3xl">×</button>
    <h2 class="text-2xl font-bold text-center mb-6">ログインする</h2>

    <form action="/login" method="POST" class="mb-4">
      <input type="text" name="username" placeholder="ユーザー名" maxlength="20" required
             class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-3 focus:outline-none focus:border-blue-500">
      <input type="password" name="password" placeholder="パスワード" required
             class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-4 focus:outline-none focus:border-blue-500">
      <button type="submit"
              class="w-full bg-black text-white py-3 rounded-2xl font-semibold hover:bg-gray-800">
        Log in
      </button>
    </form>

    <a href="/auth/google"
       class="w-full block bg-red-500 text-white py-3 rounded-2xl text-center font-semibold hover:bg-red-600 mt-2">
      Googleでログイン
    </a>

    <p class="text-center text-gray-500 mt-4">
      アカウントをお持ちでないですか？
      <a href="/signup" class="text-blue-500 hover:text-blue-700">Sign up</a>
    </p>
  </div>
</body>
</html>`);
});

// =============================
// サインアップ画面
// =============================
app.get('/signup', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>Sign up - sententia</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center relative">
  <div class="absolute top-2 left-1/2 -translate-x-1/2">
    <button onclick="location.href='/'" class="flex items-center">
      <img src="/logo.png" alt="sententia" class="h-24 w-[800px] object-contain">
    </button>
  </div>

  <div class="bg-white rounded-3xl shadow-2xl p-8 w-full max-w-lg relative mt-20">
    <button onclick="location.href='/'"
            class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-3xl">×</button>
    <h2 class="text-2xl font-bold text-center mb-6">アカウントを作成</h2>
    <form action="/signup" method="POST">
      <input type="text" name="username" placeholder="ユーザー名（20文字まで）"
             maxlength="20" required
             class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-4 focus:outline-none focus:border-blue-500">
      <input type="password" name="password" placeholder="パスワード" required
             class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-4 focus:outline-none focus:border-blue-500">
      <input type="text" name="handle" placeholder="@ユーザーID（任意、20文字まで）"
             maxlength="20"
             class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-4 focus:outline-none focus:border-blue-500">

      <div class="text-xs text-gray-600 mb-6">
        登録することで
        <button type="button" onclick="openModal('tos-modal')" class="text-blue-500 underline">利用規約</button>
        と
        <button type="button" onclick="openModal('privacy-modal')" class="text-blue-500 underline">プライバシーポリシー</button>
        に同意したものとみなされます。
      </div>

      <button type="submit"
              class="w-full bg-blue-500 text-white py-3 rounded-2xl font-semibold hover:bg-blue-600">
        作成する
      </button>
    </form>

    <a href="/auth/google"
       class="w-full block bg-red-500 text-white py-3 rounded-2xl text-center font-semibold hover:bg-red-600 mt-4">
      Googleでサインアップ / ログイン
    </a>

    <p class="text-center text-gray-500 mt-4 cursor-pointer hover:text-blue-500"
       onclick="location.href='/login-modal'">
      すでにアカウントをお持ちですか？ Log in
    </p>
  </div>

  <!-- 利用規約モーダル -->
  <div id="tos-modal" class="hidden fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-20">
    <div class="bg-white rounded-3xl shadow-2xl w-full max-w-lg mx-4 p-6 relative">
      <button onclick="closeModal('tos-modal')"
              class="absolute top-3 right-4 text-gray-400 hover:text-gray-600 text-2xl">×</button>
      <h3 class="text-xl font-bold mb-4">利用規約</h3>
      <div class="max-h-80 overflow-y-auto text-sm text-gray-700 space-y-2">
        <p>本サービス「sententia」は、ユーザーの意見やアイデアを共有するためのプラットフォームです。</p>
        <p>ユーザーは、法令および公序良俗に反する内容を投稿してはなりません。</p>
        <p>運営は、不適切と判断した投稿を削除する場合があります。</p>
        <p>本サービスは予告なく内容の変更、一時停止、終了を行うことがあります。</p>
      </div>
    </div>
  </div>

  <!-- プライバシーポリシーモーダル -->
  <div id="privacy-modal" class="hidden fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-20">
    <div class="bg-white rounded-3xl shadow-2xl w-full max-w-lg mx-4 p-6 relative">
      <button onclick="closeModal('privacy-modal')"
              class="absolute top-3 right-4 text-gray-400 hover:text-gray-600 text-2xl">×</button>
      <h3 class="text-xl font-bold mb-4">プライバシーポリシー</h3>
      <div class="max-h-80 overflow-y-auto text-sm text-gray-700 space-y-2">
        <p>本サービスは、ユーザー登録やログインに必要な最小限の情報のみを取得します。</p>
        <p>取得した情報は、認証、サービス改善、セキュリティ確保の目的のみに利用します。</p>
        <p>本人の同意なく第三者に個人情報を提供することはありません（法令に基づく場合を除く）。</p>
      </div>
    </div>
  </div>

  <script>
    function openModal(id) {
      document.getElementById(id).classList.remove('hidden');
    }
    function closeModal(id) {
      document.getElementById(id).classList.add('hidden');
    }
  </script>
</body>
</html>`);
});

// =============================
// サインアップ POST
// =============================
app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    let { handle } = req.body;

    if (!username || username.length < 1 || username.length > 20) {
      return res.send(
        '<script>alert("ユーザー名は1〜20文字で入力してください。"); history.back();</script>'
      );
    }

    if (!password) {
      return res.send(
        '<script>alert("パスワードを入力してください。"); history.back();</script>'
      );
    }

    if (handle) {
      handle = handle.trim();
      if (!handle.startsWith('@')) handle = '@' + handle;
      if (handle.length > 20) {
        return res.send(
          '<script>alert("ユーザーID（@〜）は20文字以内で入力してください。"); history.back();</script>'
        );
      }
    } else {
      handle = null;
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from('users')
      .insert({
        username,
        password: hashedPassword,
        handle
      })
      .select()
      .single();

    if (error) {
      return res.send(
        '<script>alert("サインアップエラー: ' +
          error.message +
          '"); history.back();</script>'
      );
    }

    req.login(data, () => res.redirect('/'));
  } catch (err) {
    console.error('Supabase signup error:', err);
    return res.send(
      '<script>alert("予期せぬエラーが発生しました。"); history.back();</script>'
    );
  }
});

// =============================
// ログイン POST
// =============================
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .single();

    if (error || !user || !user.password) {
      return res.send(
        '<script>alert("ユーザー名またはパスワードが違います。"); history.back();</script>'
      );
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.send(
        '<script>alert("ユーザー名またはパスワードが違います。"); history.back();</script>'
      );
    }

    req.login(user, () => res.redirect('/'));
  } catch (err) {
    console.error('Login error:', err);
    return res.send(
      '<script>alert("ログイン中にエラーが発生しました。"); history.back();</script>'
    );
  }
});

// =============================
// 設定画面
// =============================
app.get('/settings', ensureAuthenticated, (req, res) => {
  const user = req.user;
  const header = renderHeader(user, { showProfileIcon: true });
  const theme = user.theme || 'system';

  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>設定 - sententia</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">
  ${header}
  <div class="max-w-xl mx-auto pt-32 pb-16 px-4">
    <h1 class="text-2xl font-bold mb-6">設定</h1>

    <!-- ユーザー情報 -->
    <div class="bg-white rounded-2xl shadow-md p-6 mb-4">
      <button onclick="document.getElementById('user-info-form').classList.toggle('hidden')"
              class="w-full flex items-center justify-between text-left">
        <span class="font-semibold text-lg">ユーザー情報</span>
        <span class="text-gray-400 text-xl">▼</span>
      </button>

      <form id="user-info-form" action="/settings/profile" method="POST" class="mt-4 hidden">
        <label class="block mb-3 text-sm text-gray-600">ユーザー名（20文字まで）</label>
        <input type="text" name="username" maxlength="20"
               value="${user.username || ''}" required
               class="w-full px-4 py-2 border border-gray-300 rounded-xl mb-4 focus:outline-none focus:border-blue-500">

        <label class="block mb-3 text-sm text-gray-600">ユーザーID（@から始まる、20文字まで）</label>
        <input type="text" name="handle" maxlength="20"
               value="${user.handle || ''}"
               class="w-full px-4 py-2 border border-gray-300 rounded-xl mb-6 focus:outline-none focus:border-blue-500"
               placeholder="@example">

        <button type="submit"
                class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-2 rounded-full font-semibold">
          保存
        </button>
      </form>
    </div>

    <!-- 画面設定（テーマ） -->
    <div class="bg-white rounded-2xl shadow-md p-6 mb-4">
      <button onclick="document.getElementById('display-settings').classList.toggle('hidden')"
              class="w-full flex items-center justify-between text-left">
        <span class="font-semibold text-lg">画面設定</span>
        <span class="text-gray-400 text-xl">▼</span>
      </button>

      <form id="display-settings" action="/settings/theme" method="POST" class="mt-4 hidden">
        <p class="mb-3 text-sm text-gray-600">テーマ</p>
        <div class="space-y-2 mb-4 text-sm">
          <label class="flex items-center gap-2 cursor-pointer">
            <input type="radio" name="theme" value="light" ${theme === 'light' ? 'checked' : ''}>
            <span>ライト</span>
          </label>
          <label class="flex items-center gap-2 cursor-pointer">
            <input type="radio" name="theme" value="dark" ${theme === 'dark' ? 'checked' : ''}>
            <span>ダーク</span>
          </label>
          <label class="flex items-center gap-2 cursor-pointer">
            <input type="radio" name="theme" value="system" ${theme === 'system' ? 'checked' : ''}>
            <span>システム設定に合わせる</span>
          </label>
        </div>

        <button type="submit"
                class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-2 rounded-full font-semibold">
          保存
        </button>
      </form>
    </div>

    <!-- バージョン履歴 -->
    <div class="bg-white rounded-2xl shadow-md p-6 mb-4">
      <button onclick="document.getElementById('version-history').classList.toggle('hidden')"
              class="w-full flex items-center justify-between text-left">
        <span class="font-semibold text-lg">バージョン履歴</span>
        <span class="text-gray-400 text-xl">▼</span>
      </button>

      <div id="version-history" class="mt-4 hidden text-sm text-gray-700 space-y-4">
        <div>
          <p class="font-semibold">v1.0.6 (beta)</p>
          <ul class="list-disc list-inside">
            <li>いいね、返信機能追加</li>
            <li>ロゴ作成</li>
          </ul>
        </div>
        <div>
          <p class="font-semibold">v1.0.5 (beta)</p>
          <ul class="list-disc list-inside">
            <li>プロフィール追加</li>
            <li>設定追加</li>
          </ul>
        </div>
        <div>
          <p class="font-semibold">v1.0.4 (beta)</p>
          <ul class="list-disc list-inside">
            <li>ログイン機能追加</li>
            <li>Googleアカウント連携</li>
          </ul>
        </div>
        <div>
          <p class="font-semibold">v1.0.3 (beta)</p>
          <ul class="list-disc list-inside">
            <li>データ保存機能追加</li>
            <li>検索機能追加</li>
          </ul>
        </div>
        <div>
          <p class="font-semibold">v1.0.2 (beta)</p>
          <ul class="list-disc list-inside">
            <li>ホーム追加</li>
          </ul>
        </div>
        <div>
          <p class="font-semibold">v1.0.1 (beta)</p>
          <ul class="list-disc list-inside">
            <li>投稿機能追加</li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`);
});

app.post('/settings/theme', ensureAuthenticated, async (req, res) => {
  const userId = req.user.id;
  const theme = req.body.theme;

  const allowed = ['light', 'dark', 'system'];
  if (!allowed.includes(theme)) {
    return res.send(
      '<script>alert("不正なテーマが指定されました。"); history.back();</script>'
    );
  }

  const { error } = await supabase
    .from('users')
    .update({ theme })
    .eq('id', userId);

  if (error) {
    console.error('Theme update error:', error);
    return res.send(
      '<script>alert("テーマの更新中にエラーが発生しました。"); history.back();</script>'
    );
  }

  // 最新のユーザー情報を取り直してセッションに反映
  const { data: updatedUser } = await supabase
    .from('users')
    .select('*')
    .eq('id', userId)
    .single();

  req.login(updatedUser, () => {
    res.send(
      '<script>alert("テーマを保存しました。"); location.href="/settings";</script>'
    );
  });
});

// =============================
// プロフィール
// =============================
app.get('/me', ensureAuthenticated, (req, res) => {
  res.redirect('/profile/' + req.user.id);
});

app.get('/profile/:id', async (req, res) => {
  const profileUserId = req.params.id;
  const viewer = req.user;

  const { data: profileUser, error: userError } = await supabase
    .from('users')
    .select('*')
    .eq('id', profileUserId)
    .single();

  if (userError || !profileUser) {
    return res.send('<h1>ユーザーが見つかりませんでした。</h1>');
  }

  const { data: postsData } = await supabase
    .from('posts')
    .select(
      'id, user_id, type, text, time, parent_post_id, users(username, handle)'
    )
    .eq('user_id', profileUserId)
    .order('time', { ascending: false });

  const userPosts = postsData || [];

  let likedPosts = [];
  const { data: likesData } = await supabase
    .from('likes')
    .select('post_id')
    .eq('user_id', profileUserId);

  if (likesData && likesData.length > 0) {
    const postIds = likesData.map((l) => l.post_id);
    const { data: likedData } = await supabase
      .from('posts')
      .select(
        'id, user_id, type, text, time, parent_post_id, users(username, handle)'
      )
      .in('id', postIds)
      .order('time', { ascending: false });

    likedPosts = likedData || [];
  }

  const allPosts = [...userPosts, ...likedPosts];
  const likesMap = {};

  if (allPosts.length > 0) {
    const ids = [...new Set(allPosts.map((p) => p.id))];

    const { data: likesForAll } = await supabase
      .from('likes')
      .select('post_id, user_id')
      .in('post_id', ids);

    if (likesForAll) {
      likesForAll.forEach((like) => {
        if (!likesMap[like.post_id]) {
          likesMap[like.post_id] = { count: 0, likedByViewer: false };
        }
        likesMap[like.post_id].count++;
        if (viewer && like.user_id === viewer.id) {
          likesMap[like.post_id].likedByViewer = true;
        }
      });
    }
  }

  function renderPostCard(p) {
    const likeInfo = likesMap[p.id] || { count: 0, likedByViewer: false };
    const likeIcon = likeInfo.likedByViewer ? '❤️' : '🤍';

    return `
      <div class="bg-white rounded-2xl p-4 shadow-md">
        <div class="flex items-start gap-3">
          <button onclick="location.href='/profile/${p.user_id}'"
                  class="w-10 h-10 rounded-full flex items-center justify-center bg-blue-100">
            <svg viewBox="0 0 24 24" class="w-6 h-6 text-blue-500" fill="currentColor">
              <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4S8 5.79 8 8s1.79 4 4 4zm0 2c-3.33 0-6 2.24-6 5v1h12v-1c0-2.76-2.67-5-6-5z"/>
            </svg>
          </button>
          <div class="flex-1">
            <div class="flex items-center justify-between">
              <div>
                <div class="text-sm font-semibold">${p.users?.username || 'ユーザー'}</div>
                <div class="text-xs text-gray-500">${p.users?.handle || '@user'}</div>
              </div>
              <div class="flex items-center gap-2 text-xs text-gray-500">
                <span class="px-2 py-0.5 rounded-full text-xs font-medium ${
                  p.type === 'company'
                    ? 'bg-blue-100 text-blue-700'
                    : 'bg-purple-100 text-purple-700'
                }">
                  ${p.type === 'company' ? '企業' : '物事'}
                </span>
                <span>${new Date(p.time).toLocaleString('ja-JP', {
                  hour: '2-digit',
                  minute: '2-digit'
                })}</span>
              </div>
            </div>
            <p class="mt-2 text-sm whitespace-pre-wrap break-words">${p.text}</p>
            <div class="mt-3 flex items-center gap-6 text-sm text-gray-500">
              <button type="button"
                      onclick="${
                        viewer
                          ? `location.href='/?replyTo=${p.id}'`
                          : "location.href='/login-modal'"
                      }"
                      class="flex items-center gap-1 hover:text-blue-500">
                💬
              </button>
              <button type="button"
                      onclick="${
                        viewer
                          ? `handleLike('${p.id}')`
                          : "location.href='/login-modal'"
                      }"
                      class="flex items-center gap-1 hover:text-pink-500">
                <span>${likeIcon}</span><span>${likeInfo.count}</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  const header = renderHeader(viewer, { showProfileIcon: false });

  const postsHtml =
    userPosts.length === 0
      ? '<p class="text-gray-500 text-sm">まだ投稿がありません。</p>'
      : userPosts.map((p) => renderPostCard(p)).join('');

  const likesHtml =
    likedPosts.length === 0
      ? '<p class="text-gray-500 text-sm">まだいいねした投稿がありません。</p>'
      : likedPosts.map((p) => renderPostCard(p)).join('');

  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>${profileUser.username || 'ユーザー'} - プロフィール</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">
  ${header}
  <div class="max-w-2xl mx-auto pt-32 pb-16 px-4">
    <div class="bg-white rounded-2xl shadow-md p-6 mb-6">
      <div class="flex items-center gap-4">
        <div class="w-16 h-16 rounded-full flex items-center justify-center bg-blue-100">
          <svg viewBox="0 0 24 24" class="w-10 h-10 text-blue-500" fill="currentColor">
            <path d="M12 12c2.8 0 5-2.2 5-5s-2.2-5-5-5-5 2.2-5 5 2.2 5 5 5zm0 2c-3.9 0-7 2.4-7 5.3V21h14v-1.7C19 16.4 15.9 14 12 14z"/>
          </svg>
        </div>
        <div>
          <div class="text-xl font-bold">${profileUser.username || 'ユーザー'}</div>
          <div class="text-sm text-gray-500">${profileUser.handle || '@user'}</div>
        </div>
      </div>
    </div>

    <div class="flex border-b mb-4">
      <button id="tab-posts" onclick="showTab('posts')"
              class="flex-1 py-2 text-center font-semibold border-b-2 border-blue-500">
        投稿
      </button>
      <button id="tab-likes" onclick="showTab('likes')"
              class="flex-1 py-2 text-center text-gray-500 border-b-2 border-transparent">
        いいね
      </button>
    </div>

    <div id="tab-posts-panel" class="space-y-4">
      ${postsHtml}
    </div>

    <div id="tab-likes-panel" class="space-y-4 hidden">
      ${likesHtml}
    </div>
  </div>

  <script>
    function showTab(tab) {
      const postsBtn = document.getElementById('tab-posts');
      const likesBtn = document.getElementById('tab-likes');
      const postsPanel = document.getElementById('tab-posts-panel');
      const likesPanel = document.getElementById('tab-likes-panel');

      if (tab === 'posts') {
        postsBtn.classList.add('border-blue-500');
        postsBtn.classList.remove('text-gray-500');
        likesBtn.classList.remove('border-blue-500');
        likesBtn.classList.add('text-gray-500');
        postsPanel.classList.remove('hidden');
        likesPanel.classList.add('hidden');
      } else {
        likesBtn.classList.add('border-blue-500');
        likesBtn.classList.remove('text-gray-500');
        postsBtn.classList.remove('border-blue-500');
        postsBtn.classList.add('text-gray-500');
        likesPanel.classList.remove('hidden');
        postsPanel.classList.add('hidden');
      }
    }

    async function handleLike(postId) {
      try {
        const res = await fetch('/like/' + postId, { method: 'POST' });
        if (res.ok) {
          location.reload();
        } else {
          alert('いいね処理に失敗しました。');
        }
      } catch (e) {
        alert('ネットワークエラーが発生しました。');
      }
    }
  </script>
</body>
</html>`);
});

// =============================
// ホーム
// =============================
app.get('/', async (req, res) => {
  const user = req.user;
  const search = (req.query.q || '').trim();
  const replyTo = req.query.replyTo || '';

  let postsQuery = supabase
    .from('posts')
    .select(
      'id, user_id, type, text, time, parent_post_id, users(username, handle)'
    )
    .order('time', { ascending: false });

  if (search) {
    postsQuery = postsQuery.ilike('text', `%${search}%`);
  }

  const { data: postsData, error: postsError } = await postsQuery;
  const posts = postsError || !postsData ? [] : postsData;

  const likesMap = {};
  if (posts.length > 0) {
    const postIds = posts.map((p) => p.id);

    const { data: likesData } = await supabase
      .from('likes')
      .select('post_id, user_id')
      .in('post_id', postIds);

    if (likesData) {
      likesData.forEach((like) => {
        if (!likesMap[like.post_id]) {
          likesMap[like.post_id] = { count: 0, likedByUser: false };
        }
        likesMap[like.post_id].count++;
        if (user && like.user_id === user.id) {
          likesMap[like.post_id].likedByUser = true;
        }
      });
    }
  }

  const topPosts = posts.filter((p) => !p.parent_post_id);
  const repliesByParent = {};
  posts
    .filter((p) => p.parent_post_id)
    .forEach((p) => {
      if (!repliesByParent[p.parent_post_id]) {
        repliesByParent[p.parent_post_id] = [];
      }
      repliesByParent[p.parent_post_id].push(p);
    });

  function renderPostCard(p, replies) {
    const likeInfo = likesMap[p.id] || {
      count: 0,
      likedByUser: false
    };
    const likeIcon = likeInfo.likedByUser ? '❤️' : '🤍';

    const repliesHtml =
      replies && replies.length > 0
        ? `
      <div class="mt-3 border-l pl-4 space-y-2">
        ${replies
          .map(
            (r) => `
          <div class="flex items-start gap-2">
            <button onclick="location.href='/profile/${r.user_id}'"
                    class="w-8 h-8 rounded-full flex items-center justify-center bg-blue-50">
              <svg viewBox="0 0 24 24" class="w-5 h-5 text-blue-400" fill="currentColor">
                <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4S8 5.79 8 8s1.79 4 4 4zm0 2c-3.33 0-6 2.24-6 5v1h12v-1c0-2.76-2.67-5-6-5z"/>
              </svg>
            </button>
            <div class="flex-1">
              <div class="flex items-center justify-between">
                <div>
                  <div class="text-xs font-semibold">${r.users?.username || 'ユーザー'}</div>
                  <div class="text-[11px] text-gray-500">${r.users?.handle || '@user'}</div>
                </div>
                <span class="text-[11px] text-gray-400">
                  ${new Date(r.time).toLocaleString('ja-JP', {
                    hour: '2-digit',
                    minute: '2-digit'
                  })}
                </span>
              </div>
              <p class="mt-1 text-xs whitespace-pre-wrap break-words">${r.text}</p>
            </div>
          </div>
        `
          )
          .join('')}
      </div>
    `
        : '';

    return `
      <div class="bg-white rounded-2xl p-4 shadow-md">
        <div class="flex items-start gap-3">
          <button onclick="location.href='/profile/${p.user_id}'"
                  class="w-10 h-10 rounded-full flex items-center justify-center bg-blue-100">
            <svg viewBox="0 0 24 24" class="w-6 h-6 text-blue-500" fill="currentColor">
              <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4S8 5.79 8 8s1.79 4 4 4zm0 2c-3.33 0-6 2.24-6 5v1h12v-1c0-2.76-2.67-5-6-5z"/>
            </svg>
          </button>

          <div class="flex-1">
            <div class="flex items-center justify-between">
              <div>
                <div class="text-sm font-semibold">${p.users?.username || 'ユーザー'}</div>
                <div class="text-xs text-gray-500">${p.users?.handle || '@user'}</div>
              </div>
              <div class="flex items-center gap-2 text-xs text-gray-500">
                <span class="px-2 py-0.5 rounded-full text-xs font-medium ${
                  p.type === 'company'
                    ? 'bg-blue-100 text-blue-700'
                    : 'bg-purple-100 text-purple-700'
                }">
                  ${p.type === 'company' ? '企業' : '物事'}
                </span>
                <span>${new Date(p.time).toLocaleString('ja-JP', {
                  hour: '2-digit',
                  minute: '2-digit'
                })}</span>
              </div>
            </div>

            <p class="mt-2 text-sm whitespace-pre-wrap break-words">${p.text}</p>

            <div class="mt-3 flex items-center gap-6 text-sm text-gray-500">
              <button type="button"
                      onclick="${
                        user
                          ? `openPostModal('${p.id}')`
                          : "location.href='/login-modal'"
                      }"
                      class="flex items-center gap-1 hover:text-blue-500">
                💬<span>${replies ? replies.length : 0}</span>
              </button>
              <button type="button"
                      onclick="${
                        user
                          ? `handleLike('${p.id}')`
                          : "location.href='/login-modal'"
                      }"
                      class="flex items-center gap-1 hover:text-pink-500">
                <span>${likeIcon}</span><span>${likeInfo.count}</span>
              </button>
            </div>
          </div>
        </div>
        ${repliesHtml}
      </div>
    `;
  }

  const header = renderHeader(user, { showProfileIcon: true });

  const postsHtml =
    topPosts.length === 0
      ? '<p class="text-gray-500">まだ投稿がありません。</p>'
      : topPosts
          .map((p) => renderPostCard(p, repliesByParent[p.id] || []))
          .join('');

  const replyToScript = replyTo
    ? `document.addEventListener('DOMContentLoaded', () => openPostModal('${replyTo}'));`
    : '';

  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>sententia</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">
  ${header}

  <div class="max-w-2xl mx-auto pt-32 pb-32 px-4">

    <div class="relative mb-8">
      <form action="/" method="GET">
        <input type="text" name="q" value="${search}"
               placeholder="キーワードで検索"
               class="w-full pl-12 pr-6 py-4 text-lg rounded-full border border-gray-300 focus:outline-none focus:border-indigo-500">
        <svg class="absolute left-4 top-5 w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
        </svg>
      </form>
    </div>

    <h2 class="text-2xl font-bold mb-6">最近のトピック</h2>
    <div class="space-y-4">
      ${postsHtml}
    </div>
  </div>

  <button onclick="${
    user
      ? "openPostModal('')"
      : "location.href='/login-modal'"
  }"
          class="fixed bottom-6 right-6 w-44 h-14 bg-blue-500 hover:bg-blue-600 text-white rounded-full shadow-2xl flex items-center justify-center text-xl font-bold z-[100] transition-all hover:scale-105">
    投稿する
  </button>

  <div id="modal" class="hidden fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50">
    <div class="bg-white rounded-3xl shadow-2xl w-full max-w-lg mx-4 p-8 relative">
      <button onclick="closePostModal()"
              class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-3xl">×</button>

      <form action="/post" method="POST">
        <input type="hidden" name="parent_post_id" id="parent_post_id_input" value="${replyTo}">

        <div class="mb-8">
          <button type="button" onclick="this.nextElementSibling.classList.toggle('hidden')"
                  class="w-full text-left text-xl font-medium flex items-center justify-between bg-gray-100 px-6 py-4 rounded-2xl">
            <span id="selected-type">企業</span>
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M19 9l-7 7-7-7"/>
            </svg>
          </button>
          <div class="hidden mt-2 bg-white rounded-2xl shadow-lg overflow-hidden">
            <label class="block px-6 py-4 hover:bg-gray-50 cursor-pointer">
              <input type="radio" name="type" value="company" checked
                     onchange="document.getElementById('selected-type').textContent='企業'"
                     class="hidden">
              企業
            </label>
            <label class="block px-6 py-4 hover:bg-gray-50 cursor-pointer">
              <input type="radio" name="type" value="thing"
                     onchange="document.getElementById('selected-type').textContent='物事'"
                     class="hidden">
              物事
            </label>
          </div>
        </div>

        <textarea name="opinion" placeholder="意見を入力（200文字まで）" required
                  maxlength="200"
                  class="w-full h-48 p-5 text-lg border-2 border-gray-200 rounded-2xl focus:border-blue-500 focus:outline-none resize-none mb-20"></textarea>

        <button type="submit"
                class="absolute bottom-6 right-6 bg-blue-500 hover:bg-blue-600 text-white font-bold py-4 px-8 rounded-full shadow-lg transition-all hover:scale-105">
          送信
        </button>
      </form>
    </div>
  </div>

  <script>
    function openPostModal(parentId) {
      const modal = document.getElementById('modal');
      const input = document.getElementById('parent_post_id_input');
      input.value = parentId || '';
      modal.classList.remove('hidden');
    }

    function closePostModal() {
      document.getElementById('modal').classList.add('hidden');
      document.getElementById('parent_post_id_input').value = '';
    }

    ${replyToScript}

    async function handleLike(postId) {
      try {
        const res = await fetch('/like/' + postId, { method: 'POST' });
        if (res.ok) {
          location.reload();
        } else {
          alert('いいねの処理に失敗しました。');
        }
      } catch (e) {
        alert('ネットワークエラーが発生しました。');
      }
    }
  </script>
</body>
</html>`);
});

// =============================
// ログアウト
// =============================
app.post('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect('/login-modal');
  });
});

// =============================
// 投稿
// =============================
app.post('/post', ensureAuthenticated, async (req, res) => {
  const { type, opinion, parent_post_id } = req.body;

  if (!opinion || opinion.length < 1 || opinion.length > 200) {
    return res.send(
      '<script>alert("投稿は1〜200文字で入力してください。"); history.back();</script>'
    );
  }

  const insertObj = {
    user_id: req.user.id,
    type: type === 'thing' ? 'thing' : 'company',
    text: opinion
  };

  if (parent_post_id) {
    insertObj.parent_post_id = parent_post_id;
  }

  const { error } = await supabase.from('posts').insert(insertObj);

  if (error) {
    return res.send(
      '<script>alert("投稿エラー: ' +
        error.message +
        '"); history.back();</script>'
    );
  }

  res.send(
    '<script>alert("投稿完了！"); location.href = "/";</script>'
  );
});

// =============================
// いいねトグル
// =============================
app.post('/like/:postId', ensureAuthenticated, async (req, res) => {
  const postId = req.params.postId;
  const userId = req.user.id;

  try {
    const { data: existing, error: existingError } = await supabase
      .from('likes')
      .select('id')
      .eq('user_id', userId)
      .eq('post_id', postId);

    if (existingError) {
      console.error('like select error', existingError);
      return res.status(500).send('error');
    }

    const like = existing && existing.length > 0 ? existing[0] : null;

    if (like) {
      const { error: deleteError } = await supabase
        .from('likes')
        .delete()
        .eq('id', like.id);

      if (deleteError) {
        console.error('like delete error', deleteError);
        return res.status(500).send('error');
      }
    } else {
      const { error: insertError } = await supabase.from('likes').insert({
        user_id: userId,
        post_id: postId
      });

      if (insertError) {
        console.error('like insert error', insertError);
        return res.status(500).send('error');
      }
    }

    return res.status(200).send('ok');
  } catch (err) {
    console.error('like toggle error', err);
    return res.status(500).send('error');
  }
});

// =============================
// サーバ起動
// =============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('sententia 起動中', PORT);
});
