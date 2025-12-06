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
              handle,
              profile_completed: false  
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
// 言語 / 翻訳
// =============================

// ユーザーから言語を取得（未設定なら ja-JP）
function getLang(req) {
  return (req.user && req.user.lang) || 'ja-JP';
}

// 翻訳辞書（UI多言語）
function t(key, lang = 'ja-JP') {
  const ja = {
    appTitle: 'sententia',
    recentTopics: '最近のトピック',
    searchPlaceholder: 'キーワードで検索',
    login: 'ログイン',
    logout: 'ログアウト',
    signup: 'アカウントを作成',
    postButton: '投稿する',
    noPosts: 'まだ投稿がありません。',
    replies: '返信',
    settings: '設定',
    userInfo: 'ユーザー情報',
    displaySettings: '画面設定',
    languageSettings: '言語 / 地域',
    themeSettings: 'テーマ',
    versionHistory: 'バージョン履歴',
    profile: 'プロフィール',
    reply: '返信',
    back: '戻る'
  };

  const en = {
    appTitle: 'sententia',
    recentTopics: 'Recent topics',
    searchPlaceholder: 'Search by keyword',
    login: 'Log in',
    logout: 'Log out',
    signup: 'Sign up',
    postButton: 'Post',
    noPosts: 'No posts yet.',
    replies: 'Replies',
    settings: 'Settings',
    userInfo: 'User info',
    displaySettings: 'Display settings',
    languageSettings: 'Language / Region',
    themeSettings: 'Theme',
    versionHistory: 'Version history',
    profile: 'Profile',
    reply: 'Reply',
    back: 'Back'
  };

  const dict = lang === 'en-US' ? en : ja;
  return dict[key] || key;
}

// =============================
// 共通ヘルパー
// =============================
function ensureAuthenticated(req, res, next) {
  if (req.user) return next();
  return res.redirect('/login-modal');
}
// プロフィール未完了専用
function ensureProfileIncomplete(req, res, next) {
  if (!req.user) {
    return res.redirect('/login-modal');
  }
  // すでに完了していたらホームへ
  if (req.user.profile_completed) {
    return res.redirect('/');
  }
  next();
}
// 共通ヘッダー（ロゴ中央 / 左にプロフィール＋設定 / 右にログインorログアウト）
function renderHeader(user, opts = {}) {
  const lang = user?.lang || 'ja-JP';
  const showProfileIcon = opts.showProfileIcon !== false;
  const unreadCount = opts.unreadCount || 0;
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

  const rightHtml = user
    ? `
  <div class="absolute right-4 top-3 flex items-center gap-3">
    <button onclick="location.href='/notifications'"
            class="relative w-10 h-10 rounded-full border bg-white flex items-center justify-center hover:bg-gray-50">
      <!-- 🔔 アイコン本体 -->
      <svg viewBox="0 0 24 24" class="w-6 h-6 text-gray-700" fill="currentColor">
        <path d="M12 2a4 4 0 0 0-4 4v1.1C6.3 8 5 9.6 5 11.5V16l-1.5 1.5A1 1 0 0 0 4 19h16a1 1 0 0 0 .7-1.7L19 16v-4.5C19 9.6 17.7 8 16 7.1V6a4 4 0 0 0-4-4zM10 20a2 2 0 1 0 4 0h-4z"/>
      </svg>

      ${
        // ★ 未読があれば青丸バッジ表示
        unreadCount > 0
          ? `<span class="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-blue-500 border-2 border-white"></span>`
          : ''
      }
    </button>
  </div>
  `
    : `
  <div class="absolute right-4 top-3 flex items-center gap-3">
    <button onclick="location.href='/login-modal'"
            class="bg-black text-white px-5 py-2 rounded-lg font-medium hover:bg-gray-800">
      ${t('login', lang)}
    </button>
  </div>
  `;

  return `
<div class="fixed top-0 left-0 right-0 z-40 pt-0 flex justify-center">
  <button onclick="location.href='/'" class="flex items-center -mt-4">
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
  (req, res) => {
    const u = req.user;
    const needsDetails =
      !u.profile_completed || !u.birthdate || !u.gender;

    if (needsDetails) {
      return res.redirect('/signup/details');
    }
    return res.redirect('/');
  }
);

// =============================
// ログインモーダル
// =============================
app.get('/login-modal', (req, res) => {
  const lang = getLang(req);
  const _t = (key) => t(key, lang);

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
    <h2 class="text-2xl font-bold text-center mb-6">${_t('login')}</h2>

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
// サインアップ画面（ステップ1：アカウント情報だけ）
// =============================
app.get('/signup', (req, res) => {
  const lang = getLang(req);
  const _t = (key) => t(key, lang);
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
      <!-- ユーザー名 -->
      <input type="text" name="username" placeholder="ユーザー名（20文字まで）"
             maxlength="20" required
             class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-4 focus:outline-none focus:border-blue-500">

      <!-- パスワード -->
      <input type="password" name="password" placeholder="パスワード" required
             class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-4 focus:outline-none focus:border-blue-500">

      <!-- ユーザーID (@〜) -->
      <input type="text" name="handle" placeholder="@ユーザーID（任意、20文字まで）"
             maxlength="20"
             class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-6 focus:outline-none focus:border-blue-500">

      <p class="text-xs text-gray-500 mb-4">
        次の画面で、生年月日・性別・利用規約への同意を入力します。
      </p>

      <button type="submit"
              class="w-full bg-blue-500 text-white py-3 rounded-2xl font-semibold hover:bg-blue-600">
        次へ
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
        handle,
        profile_completed: false   // ★ まだ詳細未入力
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

    // いったんログインさせてから詳細入力ページへ
    req.login(data, () => res.redirect('/signup/details'));
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

    // ここで「プロフィール未完了かどうか」を判定
    const needsDetails =
      !user.profile_completed || !user.birthdate || !user.gender;

    req.login(user, () => {
      if (needsDetails) {
        // プロフィール詳細入力画面へ
        return res.redirect('/signup/details');
      }
      // 完了していればホームへ
      return res.redirect('/');
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.send(
      '<script>alert("ログイン中にエラーが発生しました。"); history.back();</script>'
    );
  }
});

// =============================
// サインアップ詳細入力（生年月日・性別・規約同意）
// =============================
app.get('/signup/details', ensureAuthenticated, (req, res) => {
  const user = req.user;

  // すでに完了しているならホームへ
  if (user.profile_completed && user.birthdate && user.gender) {
    return res.redirect('/');
  }

  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>プロフィール詳細 - sententia</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center">
  <div class="bg-white rounded-3xl shadow-2xl p-8 w-full max-w-lg relative">
    <h2 class="text-2xl font-bold text-center mb-6">プロフィール情報の入力</h2>

    <form action="/signup/details" method="POST" class="space-y-5">

      <div>
        <label class="block text-sm font-semibold mb-1">生年月日</label>
        <input type="date" name="birthdate" required
               class="w-full px-4 py-2 border border-gray-300 rounded-2xl focus:outline-none focus:border-blue-500">
      </div>

      <div>
        <span class="block text-sm font-semibold mb-1">性別</span>
        <div class="flex gap-4 text-sm">
          <label class="flex items-center gap-2">
            <input type="radio" name="gender" value="male" required>
            <span>男性</span>
          </label>
          <label class="flex items-center gap-2">
            <input type="radio" name="gender" value="female">
            <span>女性</span>
          </label>
          <label class="flex items-center gap-2">
            <input type="radio" name="gender" value="other">
            <span>その他</span>
          </label>
        </div>
      </div>

      <div class="text-xs text-gray-600 space-y-2">
        <label class="flex items-start gap-2 cursor-pointer">
          <input type="checkbox" name="agree_tos" value="1" required class="mt-1">
          <span>
            利用規約に同意します
            （<a href="javascript:void(0)" onclick="openModal('tos-modal')" class="text-blue-500 underline">内容を表示</a>）
          </span>
        </label>
        <label class="flex items-start gap-2 cursor-pointer">
          <input type="checkbox" name="agree_privacy" value="1" required class="mt-1">
          <span>
            プライバシーポリシーに同意します
            （<a href="javascript:void(0)" onclick="openModal('privacy-modal')" class="text-blue-500 underline">内容を表示</a>）
          </span>
        </label>
      </div>

      <button type="submit"
              class="w-full bg-blue-500 text-white py-3 rounded-2xl font-semibold hover:bg-blue-600">
        保存してはじめる
      </button>
    </form>
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

app.post('/signup/details', ensureAuthenticated, async (req, res) => {
  const userId = req.user.id;
  const { birthdate, gender, agree_tos, agree_privacy } = req.body;

  if (!birthdate || !gender || !agree_tos || !agree_privacy) {
    return res.send(
      '<script>alert("生年月日・性別・利用規約・プライバシーポリシーの同意は必須です。"); history.back();</script>'
    );
  }

  const { error } = await supabase
    .from('users')
    .update({
      birthdate,
      gender,
      profile_completed: true
    })
    .eq('id', userId);

  if (error) {
    console.error('signup details update error:', error);
    return res.send(
      '<script>alert("プロフィール更新中にエラーが発生しました。"); history.back();</script>'
    );
  }

  // 更新後のユーザーでセッション更新
  const { data: updatedUser } = await supabase
    .from('users')
    .select('*')
    .eq('id', userId)
    .single();

  req.login(updatedUser, () => {
    res.redirect('/');
  });
});

// =============================
// 設定画面
// =============================
app.get('/settings', ensureAuthenticated, async (req, res) => {
  const user = req.user;
  const lang = getLang(req);
  const locale = user.lang || 'ja-JP';
  let unreadCount = 0;
  if (user) {
    const { count } = await supabase
      .from('notifications')
      .select('id', { count: 'exact', head: true })
      .eq('user_id', user.id)
      .eq('read', false);

    unreadCount = count || 0;
  }

  const theme = user.theme || 'system';
  const themeClass = theme === 'dark' ? 'dark-mode' : 'bg-gray-100';

  const header = renderHeader(user, { showProfileIcon: true,unreadCount });

  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>設定 - sententia</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
  .dark-mode {
    background-color: #0d1117;
    color: #e5e7eb;
  }
  .dark-mode .post-card,
  .dark-mode .bg-white {
    background-color: #1a1f28;
    color: #f3f4f6;
  }
  .dark-mode input[type="text"],
  .dark-mode textarea,
  .dark-mode .search-box {
    background-color: #1a1f28;
    border-color: #374151;
    color: #e5e7eb;
  }
  .dark-mode .text-gray-500 {
    color: #9ca3af;
  }
  .dark-mode .border-gray-300 {
    border-color: #4b5563;
  }
  .dark-mode .shadow-md {
    box-shadow: none;
  }
  </style>
</head>
<body class="${themeClass} min-h-screen">
  ${header}
  <div class="max-w-xl mx-auto pt-32 pb-16 px-4">
    <h1 class="text-2xl font-bold mb-6">${t('settings', locale)}</h1>

    <!-- ユーザー情報 -->
    <div class="bg-white rounded-2xl shadow-md p-6 mb-4">
      <button onclick="document.getElementById('user-info-form').classList.toggle('hidden')"
              class="w-full flex items-center justify-between text-left">
        <span class="font-semibold text-lg">${t('userInfo', locale)}</span>
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
        <span class="font-semibold text-lg">${t('displaySettings', locale)}</span>
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

    <!-- 言語 / 地域設定 -->
    <div class="bg-white rounded-2xl shadow-md p-6 mb-4">
      <button onclick="document.getElementById('lang-settings').classList.toggle('hidden')"
              class="w-full flex items-center justify-between text-left">
        <span class="font-semibold text-lg">${t('languageSettings', locale)}</span>
        <span class="text-gray-400 text-xl">▼</span>
      </button>

      <form id="lang-settings" action="/settings/lang" method="POST" class="mt-4 hidden text-sm">
        <p class="mb-3 text-gray-600">表示言語と時間表示の地域を選択</p>
        <div class="space-y-2 mb-4">
          <label class="flex items-center gap-2 cursor-pointer">
            <input type="radio" name="langRegion" value="jp"
                   ${user.lang === 'ja-JP' ? 'checked' : ''}>
            <span>日本（日本語 / 日本時間）</span>
          </label>
          <label class="flex items-center gap-2 cursor-pointer">
            <input type="radio" name="langRegion" value="us"
                   ${user.lang === 'en-US' ? 'checked' : ''}>
            <span>アメリカ（英語 / 米国時間）</span>
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
        <span class="font-semibold text-lg">${t('versionHistory', locale)}</span>
        <span class="text-gray-400 text-xl">▼</span>
      </button>

      <div id="version-history" class="mt-4 hidden text-sm text-gray-700 space-y-4">
         <div>
          <p class="font-semibold">v1.0.7 (beta)</p>
          <ul class="list-disc list-inside">
            <li>ダークモード、システム同期追加</li>
            <li>投稿詳細追加</li>
            <li>言語設定追加</li>
          </ul>
        </div>
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
  
    <!-- ログアウト -->
    <div class="bg-white rounded-2xl shadow-md p-6 mb-4">
      <h2 class="font-semibold text-lg mb-2">ログアウト</h2>
      <p class="text-sm text-gray-600 mb-4">
        sententia からログアウトします。再度利用するにはログインが必要です。
      </p>
      <form action="/logout" method="POST">
        <button type="submit"
                class="w-full bg-red-500 hover:bg-red-600 text-white py-3 rounded-full font-semibold">
          ログアウトする
        </button>
      </form>
    </div>

  <script>
    (function () {
      const theme = '${theme}';
      if (theme !== 'system') return;

      const body = document.body;

      function applySystemTheme() {
        const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        if (dark) {
          body.classList.add('dark-mode');
          body.classList.remove('bg-gray-100');
        } else {
          body.classList.remove('dark-mode');
          body.classList.add('bg-gray-100');
        }
      }

      applySystemTheme();
      const mq = window.matchMedia('(prefers-color-scheme: dark)');
      mq.addEventListener('change', applySystemTheme);
    })();
  </script>
</body>
</html>`);
});

// テーマ更新
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

// 言語 / 地域更新
app.post('/settings/lang', ensureAuthenticated, async (req, res) => {
  const userId = req.user.id;
  const { langRegion } = req.body;

  let lang = 'ja-JP';
  let time_zone = 'Asia/Tokyo';

  if (langRegion === 'us') {
    lang = 'en-US';
    time_zone = 'America/Los_Angeles';
  }

  const { error } = await supabase
    .from('users')
    .update({ lang, time_zone })
    .eq('id', userId);

  if (error) {
    console.error('Lang update error:', error);
    return res.send(
      '<script>alert("言語設定の更新中にエラーが発生しました。"); history.back();</script>'
    );
  }

  const { data: updatedUser } = await supabase
    .from('users')
    .select('*')
    .eq('id', userId)
    .single();

  req.login(updatedUser, () => {
    res.send(
      '<script>alert("言語 / 地域設定を保存しました。"); location.href="/settings";</script>'
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
  const lang = getLang(req);
  const profileUserId = req.params.id;
  const viewer = req.user;
  let unreadCount = 0;
  if (viewer) {
    const { count } = await supabase
      .from('notifications')
      .select('id', { count: 'exact', head: true })
      .eq('user_id', viewer.id)
      .eq('read', false);

    unreadCount = count || 0;
  }

  const theme = viewer?.theme || 'system';
  const themeClass = theme === 'dark' ? 'dark-mode' : 'bg-gray-100';
  const locale = viewer?.lang || 'ja-JP';
  const timeZone = viewer?.time_zone || 'Asia/Tokyo';

  const header = renderHeader(viewer, {
    showProfileIcon: false,
    unreadCount
  });
  function formatTime(dateStr, opts = {}) {
    return new Date(dateStr).toLocaleString(locale, {
      timeZone,
      ...opts
    });
  }

  // プロフィール対象ユーザー
  const { data: profileUser, error: userError } = await supabase
    .from('users')
    .select('*')
    .eq('id', profileUserId)
    .single();

  if (userError || !profileUser) {
    return res.send('<h1>ユーザーが見つかりませんでした。</h1>');
  }

  // フォロー数 / フォロワー数
  let followerCount = 0;
  let followingCount = 0;
  let isFollowing = false;
  const isMe = viewer && viewer.id === profileUserId;

  // フォロワー数
  const { count: followerCountRes } = await supabase
    .from('follows')
    .select('id', { count: 'exact', head: true })
    .eq('following_id', profileUserId);
  followerCount = followerCountRes || 0;

  // フォロー数
  const { count: followingCountRes } = await supabase
    .from('follows')
    .select('id', { count: 'exact', head: true })
    .eq('follower_id', profileUserId);
  followingCount = followingCountRes || 0;

  // ログイン中ユーザーがこの人をフォローしているか
  if (viewer && !isMe) {
    const { data: followRows, error: followErr } = await supabase
      .from('follows')
      .select('id')
      .eq('follower_id', viewer.id)
      .eq('following_id', profileUserId);

    if (!followErr && followRows && followRows.length > 0) {
      isFollowing = true;
    }
  }

  // このユーザーの投稿
  const { data: postsData } = await supabase
    .from('posts')
    .select(
      'id, user_id, type, text, time, parent_post_id, users(username, handle)'
    )
    .eq('user_id', profileUserId)
    .order('time', { ascending: false });

  const userPosts = postsData || [];

  // このユーザーがいいねした投稿
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

  // いいね情報
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
      <div class="post-card bg-white rounded-2xl p-6 shadow-md">
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
                <span>${formatTime(p.time, {
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

  const postsHtml =
    userPosts.length === 0
      ? '<p class="text-gray-500 text-sm">まだ投稿がありません。</p>'
      : userPosts.map((p) => renderPostCard(p)).join('');

  const likesHtml =
    likedPosts.length === 0
      ? '<p class="text-gray-500 text-sm">まだいいねした投稿がありません。</p>'
      : likedPosts.map((p) => renderPostCard(p)).join('');

  // フォローボタンの HTML（自分のプロフィールなら表示しない）
  const followButtonHtml =
    viewer && !isMe
      ? `
      <form action="/follow/${profileUser.id}" method="POST">
        <button type="submit"
                class="px-4 py-1 rounded-full text-sm font-semibold border ${
                  isFollowing
                    ? 'bg-blue-500 text-white border-blue-500'
                    : 'bg-white text-blue-500 border-blue-500'
                }">
          ${isFollowing ? 'フォロー中' : 'フォロー'}
        </button>
      </form>
    `
      : '';

  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>${profileUser.username || 'ユーザー'} - プロフィール</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
  .dark-mode {
    background-color: #0d1117;
    color: #e5e7eb;
  }
  .dark-mode .post-card,
  .dark-mode .bg-white {
    background-color: #1a1f28;
    color: #f3f4f6;
  }
  .dark-mode input[type="text"],
  .dark-mode textarea,
  .dark-mode .search-box {
    background-color: #1a1f28;
    border-color: #374151;
    color: #e5e7eb;
  }
  .dark-mode .text-gray-500 {
    color: #9ca3af;
  }
  .dark-mode .border-gray-300 {
    border-color: #4b5563;
  }
  .dark-mode .shadow-md {
    box-shadow: none;
  }
  </style>
</head>
<body class="${themeClass} min-h-screen">
  ${header}
  <div class="max-w-2xl mx-auto pt-32 pb-16 px-4">
    <div class="bg-white rounded-2xl shadow-md p-6 mb-6">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-4">
          <div class="w-16 h-16 rounded-full flex items-center justify-center bg-blue-100">
            <svg viewBox="0 0 24 24" class="w-10 h-10 text-blue-500" fill="currentColor">
              <path d="M12 12c2.8 0 5-2.2 5-5s-2.2-5-5-5-5 2.2-5 5 2.2 5 5 5zm0 2c-3.9 0-7 2.4-7 5.3V21h14v-1.7C19 16.4 15.9 14 12 14z"/>
            </svg>
          </div>
          <div>
            <div class="text-xl font-bold">${profileUser.username || 'ユーザー'}</div>
            <div class="text-sm text-gray-500">${profileUser.handle || '@user'}</div>

            <div class="mt-2 flex items-center gap-4 text-sm">
              <span><span class="font-semibold">${followingCount}</span> フォロー中</span>
              <span><span class="font-semibold">${followerCount}</span> フォロワー</span>
            </div>
          </div>
        </div>
        ${followButtonHtml}
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

    (function () {
      const theme = '${theme}';
      if (theme !== 'system') return;

      const body = document.body;

      function applySystemTheme() {
        const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        if (dark) {
          body.classList.add('dark-mode');
          body.classList.remove('bg-gray-100');
        } else {
          body.classList.remove('dark-mode');
          body.classList.add('bg-gray-100');
        }
      }

      applySystemTheme();

      const mq = window.matchMedia('(prefers-color-scheme: dark)');
      mq.addEventListener('change', applySystemTheme);
    })();
  </script>
</body>
</html>`);
});

// =============================
// 通知一覧
// =============================
app.get('/notifications', ensureAuthenticated, async (req, res) => {
  const user = req.user;
  const theme = user.theme || 'system';
  const themeClass = theme === 'dark' ? 'dark-mode' : 'bg-gray-100';
  const header = renderHeader(user, { showProfileIcon: true });

  const locale = user.lang || 'ja-JP';
  const timeZone = user.time_zone || 'Asia/Tokyo';

  function formatTime(dateStr) {
    return new Date(dateStr).toLocaleString(locale, {
      timeZone,
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  // 自分宛ての通知を新しい順に取得
  const { data: notifs, error } = await supabase
    .from('notifications')
    .select('id, type, post_id, created_at, read, actor:actor_id(username, handle)')
    .eq('user_id', user.id)
    .order('created_at', { ascending: false })
    .limit(50);

  if (error) {
    console.error('notifications error:', error);
  }

  const list = notifs || [];

  function renderNotif(n) {
    const actorName = n.actor?.username || '誰か';
    const actorHandle = n.actor?.handle || '';
    const timeStr = formatTime(n.created_at);
    let mainText = '';

    if (n.type === 'like') {
      mainText = `${actorName} さんがあなたの投稿にいいねしました`;
    } else if (n.type === 'follow') {
      mainText = `${actorName} さんにフォローされました`;
    } else if (n.type === 'reply') {
      mainText = `${actorName} さんがあなたの投稿に返信しました`;
    } else {
      mainText = 'アクションがありました';
    }

    const link = n.post_id ? `/post/${n.post_id}` : '/';

    return `
      <a href="${link}"
         class="block rounded-2xl px-4 py-3 mb-2 ${
           n.read ? 'bg-white' : 'bg-blue-50'
         } hover:bg-blue-100 transition">
        <div class="text-sm font-semibold">${mainText}</div>
        <div class="text-xs text-gray-500 mt-1">
          ${actorHandle} ・ ${timeStr}
        </div>
      </a>
    `;
  }

  const listHtml =
    list.length === 0
      ? '<p class="text-sm text-gray-500">まだお知らせはありません。</p>'
      : list.map((n) => renderNotif(n)).join('');

  // ここで既読にする（失敗しても無視）
  if (list.length > 0) {
    supabase
      .from('notifications')
      .update({ read: true })
      .eq('user_id', user.id)
      .eq('read', false);
  }

  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>お知らせ - sententia</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
  .dark-mode {
    background-color: #0d1117;
    color: #e5e7eb;
  }
  .dark-mode .post-card,
  .dark-mode .bg-white {
    background-color: #1a1f28;
    color: #f3f4f6;
  }
  .dark-mode .text-gray-500 {
    color: #9ca3af;
  }
  .dark-mode .border-gray-300 {
    border-color: #4b5563;
  }
  </style>
</head>
<body class="${themeClass} min-h-screen">
  ${header}
  <div class="max-w-2xl mx-auto pt-32 pb-16 px-4">
    <h1 class="text-2xl font-bold mb-4">お知らせ</h1>
    <div>
      ${listHtml}
    </div>
  </div>

  <script>
    (function () {
      const theme = '${theme}';
      if (theme !== 'system') return;
      const body = document.body;
      function applySystemTheme() {
        const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        if (dark) {
          body.classList.add('dark-mode');
          body.classList.remove('bg-gray-100');
        } else {
          body.classList.remove('dark-mode');
          body.classList.add('bg-gray-100');
        }
      }
      applySystemTheme();
      const mq = window.matchMedia('(prefers-color-scheme: dark)');
      mq.addEventListener('change', applySystemTheme);
    })();
  </script>
</body>
</html>`);
});

// =============================
// 投稿詳細ページ
// =============================
app.get('/post/:id', async (req, res) => {
  const postId = req.params.id;
  const viewer = req.user || null;
  let unreadCount = 0;
  if (viewer) {
    const { count } = await supabase
      .from('notifications')
      .select('id', { count: 'exact', head: true })
      .eq('user_id', viewer.id)
      .eq('read', false);

    unreadCount = count || 0;
  }


  const theme = viewer?.theme || 'system';
  const themeClass = theme === 'dark' ? 'dark-mode' : 'bg-gray-100';
  const header = renderHeader(viewer, {
    showProfileIcon: true,
    unreadCount
  });

  const locale = viewer?.lang || 'ja-JP';
  const timeZone = viewer?.time_zone || 'Asia/Tokyo';

  function formatTime(dateStr, opts = {}) {
    return new Date(dateStr).toLocaleString(locale, {
      timeZone,
      ...opts
    });
  }

  // 投稿本体
  const { data: post, error: postError } = await supabase
    .from('posts')
    .select(
      'id, user_id, type, text, time, parent_post_id, users(username, handle)'
    )
    .eq('id', postId)
    .single();

  if (postError || !post) {
    return res.send('<h1>投稿が見つかりませんでした。</h1>');
  }

  // 返信一覧
  const { data: repliesData } = await supabase
    .from('posts')
    .select(
      'id, user_id, type, text, time, parent_post_id, users(username, handle)'
    )
    .eq('parent_post_id', postId)
    .order('time', { ascending: true });

  const replies = repliesData || [];

  // いいね取得（投稿＋返信全部）
  const allIds = [post.id, ...replies.map((r) => r.id)];
  const likesMap = {};

  if (allIds.length > 0) {
    const { data: likesForAll } = await supabase
      .from('likes')
      .select('post_id, user_id')
      .in('post_id', allIds);

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

  // メイン投稿のカード
  function renderMainPost(p) {
    const likeInfo = likesMap[p.id] || { count: 0, likedByViewer: false };
    const likeIcon = likeInfo.likedByViewer ? '❤️' : '🤍';

    const fullTime = formatTime(p.time, {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });

    return `
      <div class="post-card bg-white rounded-2xl p-6 shadow-md mb-6">
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
                <div class="text-base font-semibold">${p.users?.username || 'ユーザー'}</div>
                <div class="text-xs text-gray-500">${p.users?.handle || '@user'}</div>
              </div>
              <span class="px-2 py-0.5 rounded-full text-xs font-medium ${
                p.type === 'company'
                  ? 'bg-blue-100 text-blue-700'
                  : 'bg-purple-100 text-purple-700'
              }">
                ${p.type === 'company' ? '企業' : '物事'}
              </span>
            </div>

            <p class="mt-3 text-sm whitespace-pre-wrap break-words">${p.text}</p>

            <div class="mt-4 text-xs text-gray-500">
              ${fullTime}
            </div>

            <div class="mt-3 flex items-center gap-6 text-sm text-gray-500">
              <button type="button"
                      onclick="${
                        viewer
                          ? `openPostModal('${p.id}')`
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

  // 返信カード
  function renderReply(r) {
    const likeInfo = likesMap[r.id] || { count: 0, likedByViewer: false };
    const likeIcon = likeInfo.likedByViewer ? '❤️' : '🤍';

    const timeStr = formatTime(r.time, {
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });

    return `
      <div class="post-card bg-white rounded-2xl p-4 shadow-md">
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
              <span class="text-[11px] text-gray-400">${timeStr}</span>
            </div>
            <p class="mt-1 text-xs whitespace-pre-wrap break-words">${r.text}</p>
            <div class="mt-2 flex items-center gap-4 text-[11px] text-gray-500">
              <button type="button"
                      onclick="${
                        viewer
                          ? `openPostModal('${post.id}')`
                          : "location.href='/login-modal'"
                      }"
                      class="flex items-center gap-1 hover:text-blue-500">
                💬
              </button>
              <button type="button"
                      onclick="${
                        viewer
                          ? `handleLike('${r.id}')`
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

  const repliesHtml =
    replies.length === 0
      ? '<p class="text-xs text-gray-500">まだ返信がありません。</p>'
      : replies.map((r) => renderReply(r)).join('');

  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>投稿詳細 - sententia</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
  .dark-mode {
    background-color: #0d1117;
    color: #e5e7eb;
  }
  .dark-mode .post-card,
  .dark-mode .bg-white {
    background-color: #1a1f28;
    color: #f3f4f6;
  }
  .dark-mode input[type="text"],
  .dark-mode textarea,
  .dark-mode .search-box {
    background-color: #1a1f28;
    border-color: #374151;
    color: #e5e7eb;
  }
  .dark-mode .text-gray-500 {
    color: #9ca3af;
  }
  .dark-mode .border-gray-300 {
    border-color: #4b5563;
  }
  .dark-mode .shadow-md {
    box-shadow: none;
  }
  </style>
</head>
<body class="${themeClass} min-h-screen">
  ${header}

  <div class="max-w-2xl mx-auto pt-32 pb-16 px-4">
    <button onclick="history.back()"
            class="text-sm text-blue-500 hover:underline mb-4">&larr; 戻る</button>

    ${renderMainPost(post)}

    <h2 class="text-sm font-semibold mb-2">返信</h2>
    <div class="space-y-2">
      ${repliesHtml}
    </div>
  </div>

  <!-- 返信用モーダル -->
  <div id="modal" class="hidden fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50">
    <div class="bg-white rounded-3xl shadow-2xl w-full max-w-lg mx-4 p-8 relative">
      <button onclick="closePostModal()"
              class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-3xl">×</button>

      <form action="/post" method="POST">
        <input type="hidden" name="parent_post_id" id="parent_post_id_input" value="${post.id}">
        <div class="mb-4 text-sm text-gray-600">
          返信を書く
        </div>
        <textarea name="opinion" placeholder="意見を入力（200文字まで）" required
                  maxlength="200"
                  class="w-full h-32 p-4 text-sm border-2 border-gray-200 rounded-2xl focus:border-blue-500 focus:outline-none resize-none mb-4"></textarea>

        <input type="hidden" name="type" value="${post.type}">

        <button type="submit"
                class="bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-6 rounded-full shadow-lg transition-all hover:scale-105 absolute bottom-6 right-6">
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

    (function () {
      const theme = '${theme}';
      if (theme !== 'system') return;

      const body = document.body;

      function applySystemTheme() {
        const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        if (dark) {
          body.classList.add('dark-mode');
          body.classList.remove('bg-gray-100');
        } else {
          body.classList.remove('dark-mode');
          body.classList.add('bg-gray-100');
        }
      }

      applySystemTheme();

      const mq = window.matchMedia('(prefers-color-scheme: dark)');
      mq.addEventListener('change', applySystemTheme);
    })();
  </script>
</body>
</html>`);
});

// =============================
// ホーム
// =============================
app.get('/', async (req, res) => {
  const user = req.user;
  const lang = getLang(req);
  const locale = user?.lang || 'ja-JP';
  const timeZone = user?.time_zone || 'Asia/Tokyo';

  function formatTime(dateStr, opts = {}) {
    return new Date(dateStr).toLocaleString(locale, {
      timeZone,
      ...opts
    });
  }
  let unreadCount = 0;
  if (user) {
    const { count } = await supabase
      .from('notifications')
      .select('id', { count: 'exact', head: true })
      .eq('user_id', user.id)
      .eq('read', false) 

    unreadCount = count || 0;
  }

  const search = (req.query.q || '').trim();
  const replyTo = req.query.replyTo || '';
  const theme = user?.theme || 'system';
  const themeClass = theme === 'dark' ? 'dark-mode' : 'bg-gray-100';
  const header = renderHeader(user, { showProfileIcon: true, unreadCount });

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

    const replyCount = replies ? replies.length : 0;

    return `
      <div class="post-card bg-white rounded-2xl p-6 shadow-md">
        <div class="flex items-start gap-3">
          <button onclick="location.href='/profile/${p.user_id}'"
                  class="w-10 h-10 rounded-full flex items-center justify-center bg-blue-100">
            <svg viewBox="0 0 24 24" class="w-6 h-6 text-blue-500" fill="currentColor">
              <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4S8 5.79 8 8s1.79 4 4 4zm0 2c-3.33 0-6 2.24-6 5v1h12v-1c0-2.76-2.67-5-6-5z"/>
            </svg>
          </button>

          <div class="flex-1">
            <button type="button"
                    onclick="location.href='/post/${p.id}'"
                    class="w-full text-left">
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
                  <span>${formatTime(p.time, {
                    hour: '2-digit',
                    minute: '2-digit'
                  })}</span>
                </div>
              </div>

              <p class="mt-2 text-sm whitespace-pre-wrap break-words">${p.text}</p>
            </button>

            <div class="mt-3 flex items-center gap-6 text-sm text-gray-500">
              <button type="button"
                      onclick="${
                        user
                          ? `openPostModal('${p.id}')`
                          : "location.href='/login-modal'"
                      }"
                      class="flex items-center gap-1 hover:text-blue-500">
                💬<span>${replyCount}</span>
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
      </div>
    `;
  }

  const postsHtml =
    topPosts.length === 0
      ? `<p class="text-gray-500">${t('noPosts', locale)}</p>`
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
  <style>
  .dark-mode {
    background-color: #0d1117;
    color: #e5e7eb;
  }
  .dark-mode .post-card,
  .dark-mode .bg-white {
    background-color: #1a1f28;
    color: #f3f4f6;
  }
  .dark-mode input[type="text"],
  .dark-mode textarea,
  .dark-mode .search-box {
    background-color: #1a1f28;
    border-color: #374151;
    color: #e5e7eb;
  }
  .dark-mode .text-gray-500 {
    color: #9ca3af;
  }
  .dark-mode .border-gray-300 {
    border-color: #4b5563;
  }
  .dark-mode .shadow-md {
    box-shadow: none;
  }
  </style>
</head>
<body class="${themeClass} min-h-screen">
  ${header}

  <div class="max-w-2xl mx-auto pt-32 pb-32 px-4">

    <div class="relative mb-8">
      <form action="/" method="GET">
        <input type="text" name="q" value="${search}"
               placeholder="${t('searchPlaceholder', locale)}"
               class="search-box w-full pl-12 pr-6 py-4 text-lg rounded-full border border-gray-300 focus:outline-none focus:border-indigo-500">
        <svg class="absolute left-4 top-5 w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
        </svg>
      </form>
    </div>

    <h2 class="text-2xl font-bold mb-6">${t('recentTopics', locale)}</h2>
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
    ${t('postButton', locale)}
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

    (function () {
      const theme = '${theme}';
      if (theme !== 'system') return;

      const body = document.body;

      function applySystemTheme() {
        const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        if (dark) {
          body.classList.add('dark-mode');
          body.classList.remove('bg-gray-100');
        } else {
          body.classList.remove('dark-mode');
          body.classList.add('bg-gray-100');
        }
      }

      applySystemTheme();
      const mq = window.matchMedia('(prefers-color-scheme: dark)');
      mq.addEventListener('change', applySystemTheme);
    })();
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

  const { data: inserted, error } = await supabase
    .from('posts')
    .insert(insertObj)
    .select()
    .single();

  if (error) {
    return res.send(
      '<script>alert("投稿エラー: ' +
        error.message +
        '"); history.back();</script>'
    );
  }

  // ★ 親投稿への返信なら通知
  if (parent_post_id) {
    try {
      const { data: parentPost } = await supabase
        .from('posts')
        .select('user_id')
        .eq('id', parent_post_id)
        .single();

      if (parentPost && parentPost.user_id !== req.user.id) {
        await supabase.from('notifications').insert({
          user_id: parentPost.user_id,
          actor_id: req.user.id,
          type: 'reply',
          post_id: inserted.id
        });
      }
    } catch (e) {
      console.error('create reply notification error', e);
    }
  }

  res.send('<script>alert("投稿完了！"); location.href = "/";</script>');
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
      // すでにいいね → 解除
      const { error: deleteError } = await supabase
        .from('likes')
        .delete()
        .eq('id', like.id);

      if (deleteError) {
        console.error('like delete error', deleteError);
        return res.status(500).send('error');
      }
    } else {
      // まだ → いいね
      const { error: insertError } = await supabase.from('likes').insert({
        user_id: userId,
        post_id: postId
      });

      if (insertError) {
        console.error('like insert error', insertError);
        return res.status(500).send('error');
      }

      // ★ 通知を作成
      try {
        const { data: post } = await supabase
          .from('posts')
          .select('user_id')
          .eq('id', postId)
          .single();

        if (post && post.user_id !== userId) {
          await supabase.from('notifications').insert({
            user_id: post.user_id,
            actor_id: userId,
            type: 'like',
            post_id: postId
          });
        }
      } catch (e) {
        console.error('create like notification error', e);
      }
    }

    return res.status(200).send('ok');
  } catch (err) {
    console.error('like toggle error', err);
    return res.status(500).send('error');
  }
});

// =============================
// フォロー / アンフォロー
// =============================
app.post('/follow/:targetId', ensureAuthenticated, async (req, res) => {
  const followerId = req.user.id;
  const targetId = req.params.targetId;

  if (followerId === targetId) {
    return res.send(
      '<script>alert("自分自身をフォローすることはできません。"); history.back();</script>'
    );
  }

  try {
    // 既にフォローしているか？
    const { data: rows, error: selectErr } = await supabase
      .from('follows')
      .select('id')
      .eq('follower_id', followerId)
      .eq('following_id', targetId);

    if (selectErr) {
      console.error('follow select error', selectErr);
      return res.send(
        '<script>alert("フォロー状態の確認でエラーが発生しました。"); history.back();</script>'
      );
    }

    if (rows && rows.length > 0) {
      // すでにフォロー → アンフォローする
      const followId = rows[0].id;
      const { error: delErr } = await supabase
        .from('follows')
        .delete()
        .eq('id', followId);

      if (delErr) {
        console.error('unfollow error', delErr);
        return res.send(
          '<script>alert("フォロー解除に失敗しました。"); history.back();</script>'
        );
      }
    } else {
      // まだフォローしていない → フォローする
      const { error: insErr } = await supabase.from('follows').insert({
        follower_id: followerId,
        following_id: targetId
      });

      if (insErr) {
        console.error('follow insert error', insErr);
        return res.send(
          '<script>alert("フォローに失敗しました。"); history.back();</script>'
        );
      }

      // ★ 通知作成（フォローされた側）
      try {
        await supabase.from('notifications').insert({
          user_id: targetId,
          actor_id: followerId,
          type: 'follow',
          post_id: null
        });
      } catch (e) {
        console.error('create follow notification error', e);
      }
    }

    // 元のプロフィールに戻す
    res.redirect('back');
  } catch (err) {
    console.error('follow toggle error', err);
    return res.send(
      '<script>alert("フォロー処理中にエラーが発生しました。"); history.back();</script>'
    );
  }
});

// =============================
// サーバ起動
// =============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('sententia 起動中', PORT);
});
