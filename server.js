const express = require('express');
const session = require('express-session');
const { default: RedisStore } = require('connect-redis');
const Redis = require('ioredis');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// プロキシ環境向け（Render 等）
app.set('trust proxy', 1);

// Redisクライアント
const redisClient = new Redis(process.env.UPSTASH_REDIS_URL);

// セッション設定
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
      secure: false, // デバッグ優先。本番 HTTPS では true 推奨
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Supabaseクライアント
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// プロフィール完成チェック
function needsOnboarding(user) {
  if (!user) return true;
  return !(
    user.birthday &&
    user.gender &&
    user.handle &&
    user.tos_agreed_at &&
    user.privacy_agreed_at
  );
}

// Google OAuth設定
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: '/auth/google/callback'
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let { data: user } = await supabase
          .from('users')
          .select('*')
          .eq('google_id', profile.id)
          .single();

        if (!user) {
          const { data, error } = await supabase
            .from('users')
            .insert({
              google_id: profile.id,
              username:
                profile.displayName ||
                profile.emails[0].value.split('@')[0],
              email: profile.emails[0].value
            })
            .select()
            .single();

          if (error) return done(error);
          user = data;
        }

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

// passport セッション用
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', id)
      .single();
    if (error) return done(error);
    return done(null, user);
  } catch (e) {
    return done(e);
  }
});

// OAuthルート
app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login-modal' }),
  (req, res) => {
    if (needsOnboarding(req.user)) {
      return res.redirect('/onboarding');
    }
    return res.redirect('/');
  }
);

// ログイン画面
app.get('/login-modal', (req, res) => {
  if (req.user) return res.redirect('/');

  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - sententia</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center relative">
  <div class="absolute inset-0 z-0">
    <div class="fixed top-6 left-6 flex items-center gap-4">
      <h1 class="text-3xl font-bold text-indigo-600 cursor-pointer" onclick="location.href='/'">
        sententia
      </h1>
    </div>
    <div class="absolute inset-0 bg-black bg-opacity-50"></div>
  </div>

  <div class="bg-white rounded-3xl shadow-2xl p-8 w-full max-w-lg relative z-10">
    <button onclick="location.href='/'" class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-3xl">×</button>
    <h2 class="text-2xl font-bold text-center mb-6">ログインする</h2>

    <form action="/login" method="POST" class="mb-4">
      <input
        type="text"
        name="username"
        placeholder="ユーザー名"
        required
        class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-3 focus:outline-none focus:border-blue-500"
      >
      <input
        type="password"
        name="password"
        placeholder="パスワード"
        required
        class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-4 focus:outline-none focus:border-blue-500"
      >
      <button
        type="submit"
        class="w-full bg-blue-500 text-white py-3 rounded-2xl font-semibold hover:bg-blue-600">
        ログイン
      </button>
    </form>

    <p class="text-center text-gray-500 mb-3">または</p>

    <a href="/auth/google"
       class="w-full block bg-red-500 text-white py-3 rounded-2xl text-center font-semibold hover:bg-red-600">
      Googleでログイン
    </a>

    <p class="text-center text-gray-500 mt-4">
      アカウントをお持ちでないですか？
    </p>
    <a href="/signup"
       class="w-full block text-center text-blue-500 hover:text-blue-700 mt-1">
      Sign up
    </a>
  </div>
</body>
</html>`);
});

// サインアップ画面
app.get('/signup', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign up - sententia</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center">
  <div class="bg-white rounded-3xl shadow-2xl p-8 w-full max-w-lg relative">
    <button onclick="location.href='/'" class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-3xl">×</button>
    <h2 class="text-2xl font-bold text-center mb-6">アカウントを作成</h2>

    <form action="/signup" method="POST" class="mb-4">
      <input
        type="text"
        name="username"
        placeholder="ユーザー名"
        required
        class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-4 focus:outline-none focus:border-blue-500">
      <input
        type="password"
        name="password"
        placeholder="パスワード"
        required
        class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-4 focus:outline-none focus:border-blue-500">
      <button
        type="submit"
        class="w-full bg-blue-500 text-white py-3 rounded-2xl font-semibold hover:bg-blue-600">
        作成する
      </button>
    </form>

    <p class="text-center text-gray-500 mb-3">または</p>

    <a href="/auth/google"
       class="w-full block bg-red-500 text-white py-3 rounded-2xl text-center font-semibold hover:bg-red-600">
      Googleでログイン / 登録
    </a>

    <p class="text-center text-gray-500 mt-4 cursor-pointer hover:text-blue-500" onclick="location.href='/login-modal'">
      すでにアカウントをお持ちですか？ Log in
    </p>
  </div>
</body>
</html>`);
});

// ローカルサインアップ
app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from('users')
      .insert({ username, password: hashedPassword })
      .select()
      .single();

    if (error) {
      console.error('Supabase signup error:', error);

      if (error.code === '23505') {
        return res.send(`
          <script>
            alert("そのユーザー名はすでに使われています。別のユーザー名を入力してください。");
            history.back();
          </script>
        `);
      }

      return res.send(`
        <script>
          alert("エラー: ${error.message}");
          history.back();
        </script>
      `);
    }

    return res.redirect('/login-modal');
  } catch (e) {
    console.error('POST /signup error:', e);
    return res.send(`
      <script>
        alert("サインアップ中にサーバーエラーが発生しました");
        history.back();
      </script>
    `);
  }
});

// ローカルログイン
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const { data: user, error } = await supabase
      .from('users')
      .select(
        'id, username, password, birthday, gender, handle, tos_agreed_at, privacy_agreed_at'
      )
      .eq('username', username)
      .single();

    if (error || !user || !user.password) {
      return res.send(
        '<script>alert("ユーザー名またはパスワードが違います"); history.back();</script>'
      );
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.send(
        '<script>alert("ユーザー名またはパスワードが違います"); history.back();</script>'
      );
    }

    req.login(user, (err) => {
      if (err) {
        console.error('req.login error:', err);
        return res.send(
          '<script>alert("ログイン中にエラーが発生しました"); history.back();</script>'
        );
      }

      if (needsOnboarding(user)) {
        return res.redirect('/onboarding');
      }
      return res.redirect('/');
    });
  } catch (e) {
    console.error('POST /login unexpected error:', e);
    return res.send(
      '<script>alert("サーバーエラーが発生しました"); history.back();</script>'
    );
  }
});

// オンボーディング画面（追加情報登録）
app.get('/onboarding', (req, res) => {
  if (!req.user) return res.redirect('/login-modal');

  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>プロフィール登録 - sententia</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center">
  <div class="bg-white rounded-3xl shadow-2xl p-8 w-full max-w-lg relative">
    <button onclick="location.href='/'" class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-3xl">×</button>
    <h2 class="text-2xl font-bold text-center mb-6">プロフィールを完成させる</h2>

    <form action="/onboarding" method="POST" class="space-y-4">
      <div>
        <label class="block text-sm font-medium mb-1">生年月日</label>
        <!-- required を外してブラウザのエラーを消し、サーバー側でチェック -->
        <input type="date" name="birthday"
          class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:outline-none focus:border-blue-500">
      </div>

      <div>
        <label class="block text-sm font-medium mb-1">性別</label>
        <select name="gender"
          class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:outline-none focus:border-blue-500">
          <option value="">選択してください</option>
          <option value="female">女性</option>
          <option value="male">男性</option>
          <option value="other">その他</option>
          <option value="no_answer">回答しない</option>
        </select>
      </div>

      <div>
        <label class="block text-sm font-medium mb-1">ユーザーID（@から始まる）</label>
        <input type="text" name="handle" placeholder="@example"
          class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:outline-none focus:border-blue-500">
      </div>

      <div class="space-y-2 text-sm">
        <label class="flex items-center gap-2">
          <input type="checkbox" name="agree_tos">
          <span>
            <button type="button" onclick="openModal('terms-modal')" class="text-blue-500 underline">
              利用規約
            </button> に同意します
          </span>
        </label>
        <label class="flex items-center gap-2">
          <input type="checkbox" name="agree_privacy">
          <span>
            <button type="button" onclick="openModal('privacy-modal')" class="text-blue-500 underline">
              プライバシーポリシー
            </button> に同意します
          </span>
        </label>
      </div>

      <button type="submit"
        class="w-full mt-4 bg-blue-500 text-white py-3 rounded-2xl font-semibold hover:bg-blue-600">
        登録する
      </button>
    </form>
  </div>

  <!-- 利用規約モーダル -->
  <div id="terms-modal" class="hidden fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50">
    <div class="bg-white rounded-3xl shadow-2xl w-full max-w-2xl mx-4 p-8 relative max-h-[80vh] overflow-y-auto">
      <button onclick="closeModal('terms-modal')" class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-3xl">×</button>
      <h2 class="text-2xl font-bold mb-4">sententia 利用規約</h2>
      <p class="text-sm text-gray-500 mb-4">最終更新日: 2025年1月1日（例）</p>

      <h3 class="text-lg font-semibold mt-4 mb-2">第1条（適用）</h3>
      <p class="mb-3">
        本規約は、ユーザーが sententia（以下「本サービス」）を利用する際の一切の行為に適用されます。
        ユーザーは、本サービスを利用することにより、本規約に同意したものとみなされます。
      </p>

      <h3 class="text-lg font-semibold mt-4 mb-2">第2条（アカウント）</h3>
      <p class="mb-3">
        ユーザーは、正確かつ最新の情報をもってアカウントを作成し、その管理責任を負うものとします。
        アカウント情報の不正利用等が発生した場合でも、本サービス運営者は一切の責任を負いません。
      </p>

      <h3 class="text-lg font-semibold mt-4 mb-2">第3条（禁止事項）</h3>
      <ul class="list-disc pl-6 mb-3 space-y-1">
        <li>法令または公序良俗に反する行為</li>
        <li>他のユーザーまたは第三者に対する誹謗中傷・嫌がらせ行為</li>
        <li>本サービスの運営を妨害する行為</li>
        <li>不正アクセス、なりすまし等の不正行為</li>
      </ul>

      <h3 class="text-lg font-semibold mt-4 mb-2">第4条（投稿内容の取り扱い）</h3>
      <p class="mb-3">
        ユーザーは、自らが投稿した内容について必要な権利を有しているものとし、本サービス運営者に対して、
        サービスの提供・改善・研究・分析等の目的で投稿内容を利用する非独占的な権利を許諾するものとします。
      </p>

      <h3 class="text-lg font-semibold mt-4 mb-2">第5条（免責）</h3>
      <p class="mb-3">
        本サービスは、提供する情報の正確性・完全性・有用性について保証するものではありません。
        ユーザーは自己責任において本サービスを利用するものとし、利用により生じたいかなる損害についても、
        本サービス運営者は責任を負いません。
      </p>

      <h3 class="text-lg font-semibold mt-4 mb-2">第6条（規約の変更）</h3>
      <p class="mb-3">
        本サービス運営者は、必要に応じて本規約を変更することができるものとします。
        変更後の本規約は、本サービス上に掲示された時点で効力を生じるものとします。
      </p>
    </div>
  </div>

  <!-- プライバシーポリシーモーダル -->
  <div id="privacy-modal" class="hidden fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50">
    <div class="bg-white rounded-3xl shadow-2xl w-full max-w-2xl mx-4 p-8 relative max-h-[80vh] overflow-y-auto">
      <button onclick="closeModal('privacy-modal')" class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-3xl">×</button>
      <h2 class="text-2xl font-bold mb-4">sententia プライバシーポリシー</h2>
      <p class="text-sm text-gray-500 mb-4">最終更新日: 2025年1月1日（例）</p>

      <h3 class="text-lg font-semibold mt-4 mb-2">第1条（収集する情報）</h3>
      <p class="mb-3">
        本サービスは、アカウント登録時にユーザー名、メールアドレス、パスワード、プロフィール情報（生年月日・性別・ユーザーIDなど）を収集します。
        また、投稿内容やアクセスログ、利用状況等の情報を取得する場合があります。
      </p>

      <h3 class="text-lg font-semibold mt-4 mb-2">第2条（利用目的）</h3>
      <ul class="list-disc pl-6 mb-3 space-y-1">
        <li>本サービスの提供および運営のため</li>
        <li>不正利用の防止・対策のため</li>
        <li>サービス品質の向上、新機能の開発のため</li>
        <li>お問い合わせへの対応のため</li>
      </ul>

      <h3 class="text-lg font-semibold mt-4 mb-2">第3条（第三者提供）</h3>
      <p class="mb-3">
        法令に基づく場合を除き、ユーザーの同意なく個人情報を第三者に提供することはありません。
      </p>

      <h3 class="text-lg font-semibold mt-4 mb-2">第4条（安全管理）</h3>
      <p class="mb-3">
        本サービスは、ユーザー情報への不正アクセス、紛失、改ざん、漏えい等を防止するために、適切な安全管理措置を講じます。
      </p>

      <h3 class="text-lg font-semibold mt-4 mb-2">第5条（ユーザーによる開示・訂正・削除）</h3>
      <p class="mb-3">
        ユーザーは、本サービス所定の方法により、自身の登録情報の閲覧・訂正・削除を行うことができます。
      </p>

      <h3 class="text-lg font-semibold mt-4 mb-2">第6条（プライバシーポリシーの変更）</h3>
      <p class="mb-3">
        本ポリシーの内容は、必要に応じて変更することがあります。
        変更後の内容は、本サービス上に掲示した時点で効力を生じるものとします。
      </p>
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

// オンボーディング POST（生年月日などサーバー側バリデーション）
app.post('/onboarding', async (req, res) => {
  if (!req.user) return res.redirect('/login-modal');

  try {
    let { birthday, gender, handle, agree_tos, agree_privacy } = req.body;

    if (!birthday) {
      return res.send(`
        <script>
          alert("生年月日を入力してください");
          history.back();
        </script>
      `);
    }
    if (!gender) {
      return res.send(`
        <script>
          alert("性別を選択してください");
          history.back();
        </script>
      `);
    }
    if (!handle || !handle.trim()) {
      return res.send(`
        <script>
          alert("ユーザーID（@）を入力してください");
          history.back();
        </script>
      `);
    }

    handle = handle.trim();
    if (!handle.startsWith('@')) {
      handle = '@' + handle;
    }

    if (!agree_tos || !agree_privacy) {
      return res.send(`
        <script>
          alert("利用規約とプライバシーポリシーへの同意が必要です。");
          history.back();
        </script>
      `);
    }

    const now = new Date().toISOString();

    const { error } = await supabase
      .from('users')
      .update({
        birthday,
        gender,
        handle,
        tos_agreed_at: now,
        privacy_agreed_at: now
      })
      .eq('id', req.user.id);

    if (error) {
      console.error('Onboarding update error:', error);

      if (error.code === '23505') {
        return res.send(`
          <script>
            alert("そのユーザーID（@）はすでに使われています。別のIDを入力してください。");
            history.back();
          </script>
        `);
      }

      return res.send(`
        <script>
          alert("プロフィール更新中にエラーが発生しました: ${error.message}");
          history.back();
        </script>
      `);
    }

    return res.redirect('/');
  } catch (e) {
    console.error('POST /onboarding error:', e);
    return res.send(`
      <script>
        alert("プロフィール更新中にサーバーエラーが発生しました");
        history.back();
      </script>
    `);
  }
});

// プロフィールページ（X風・水色アイコン）
app.get('/profile', async (req, res) => {
  if (!req.user) return res.redirect('/login-modal');

  const { data: postsData } = await supabase
    .from('posts')
    .select('*, users(username)')
    .eq('user_id', req.user.id)
    .order('time', { ascending: false });

  const posts = postsData || [];

  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${req.user.username} - プロフィール | sententia</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">

  <!-- 左上タイトル -->
  <div class="fixed top-6 left-6 z-40 flex items-center gap-4">
    <h1 class="text-3xl font-bold text-indigo-600 cursor-pointer" onclick="location.href='/'">
      sententia
    </h1>
  </div>

  <!-- 右上 設定アイコン + Log out -->
  <form id="logout-form" action="/logout" method="POST" style="display:none;"></form>

  <button
    onclick="location.href='/settings';"
    class="fixed top-6 right-20 bg-white border border-gray-300 text-gray-700 px-3 py-2 rounded-full font-medium z-40 hover:bg-gray-50 flex items-center justify-center shadow-sm">
    <!-- 歯車アイコン -->
    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" viewBox="0 0 20 20" fill="currentColor">
      <path d="M11.983 1.904a1 1 0 00-1.966 0l-.264 1.325a5.52 5.52 0 00-1.518.878l-1.28-.513a1 1 0 00-1.316.59L3.66 6.362a1 1 0 00.228 1.024l.94.94a5.52 5.52 0 000 1.748l-.94.94a1 1 0 00-.228 1.024l.98 2.178a1 1 0 001.316.59l1.28-.513c.46.37.968.673 1.518.878l.264 1.325a1 1 0 001.966 0l.264-1.325a5.52 5.52 0 001.518-.878l1.28.513a1 1 0 001.316-.59l.98-2.178a1 1 0 00-.228-1.024l-.94-.94a5.52 5.52 0 000-1.748l.94-.94a1 1 0 00.228-1.024l-.98-2.178a1 1 0 00-1.316-.59l-1.28.513a5.52 5.52 0 00-1.518-.878l-.264-1.325zM10 8a2 2 0 110 4 2 2 0 010-4z" />
    </svg>
  </button>

  <button
    onclick="document.getElementById('logout-form').submit();"
    class="fixed top-6 right-6 bg-black text-white px-6 py-2 rounded-lg font-medium z-40 hover:bg-gray-800">
    Log out
  </button>

  <!-- メイン -->
  <div class="max-w-2xl mx-auto pt-24 pb-24 px-4">

    <!-- プロフィールカード -->
    <div class="bg-white rounded-3xl shadow-md p-6 mb-8">
      <div class="flex items-center gap-4">
        <!-- 水色ベースのオリジナル人影アイコン -->
        <div class="w-16 h-16 rounded-full bg-gradient-to-br from-sky-400 to-cyan-500 flex items-center justify-center overflow-hidden shadow-md">
          <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" class="w-11 h-11">
            <circle cx="12" cy="8" r="4" fill="#e0f2fe"/>
            <path d="M4 19c1.2-3.2 4-5 8-5s6.8 1.8 8 5" fill="#bae6fd" />
          </svg>
        </div>
        <div>
          <div class="text-xl font-bold">${req.user.username || ''}</div>
          <div class="text-sm text-gray-500">${req.user.handle || ''}</div>
        </div>
      </div>
    </div>

    <!-- ユーザーの投稿一覧 -->
    <h2 class="text-xl font-bold mb-4">投稿</h2>
    <div class="space-y-4">
      ${
        posts.length === 0
          ? '<p class="text-gray-500 text-sm">まだ投稿はありません。</p>'
          : posts
              .map(
                (p) => `
        <div class="bg-white rounded-2xl p-6 shadow-md">
          <div class="flex items-center gap-3 mb-2">
            <span class="px-4 py-1 rounded-full text-sm font-medium ${
              p.type === 'company'
                ? 'bg-blue-100 text-blue-700'
                : 'bg-purple-100 text-purple-700'
            }">
              ${p.type === 'company' ? '企業' : '物事'}
            </span>
            <span class="text-gray-500 text-sm">
              ${
                p.time
                  ? new Date(p.time).toLocaleString('ja-JP', {
                      month: '2-digit',
                      day: '2-digit',
                      hour: '2-digit',
                      minute: '2-digit'
                    })
                  : ''
              }
            </span>
          </div>
          <p class="text-lg">${p.text}</p>
        </div>
      `
              )
              .join('')
      }
    </div>
  </div>

</body>
</html>`);
});

// 設定画面（ユーザー情報メニュー → ユーザー名/ID変更）
app.get('/settings', (req, res) => {
  if (!req.user) return res.redirect('/login-modal');

  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>設定 - sententia</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">

  <!-- 左上タイトル -->
  <div class="fixed top-6 left-6 z-40 flex items-center gap-4">
    <h1 class="text-3xl font-bold text-indigo-600 cursor-pointer" onclick="location.href='/'">
      sententia
    </h1>
  </div>

  <!-- 右上 設定アイコン + Log out -->
  <form id="logout-form" action="/logout" method="POST" style="display:none;"></form>

  <button
    onclick="location.href='/settings';"
    class="fixed top-6 right-20 bg-white border border-gray-300 text-gray-700 px-3 py-2 rounded-full font-medium z-40 hover:bg-gray-50 flex items-center justify-center shadow-sm">
    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" viewBox="0 0 20 20" fill="currentColor">
      <path d="M11.983 1.904a1 1 0 00-1.966 0l-.264 1.325a5.52 5.52 0 00-1.518.878l-1.28-.513a1 1 0 00-1.316.59L3.66 6.362a1 1 0 00.228 1.024l.94.94a5.52 5.52 0 000 1.748l-.94.94a1 1 0 00-.228 1.024l.98 2.178a1 1 0 001.316.59l1.28-.513c.46.37.968.673 1.518.878l.264 1.325a1 1 0 001.966 0l.264-1.325a5.52 5.52 0 001.518-.878l1.28.513a1 1 0 001.316-.59l.98-2.178a1 1 0 00-.228-1.024l-.94-.94a5.52 5.52 0 000-1.748l.94-.94a1 1 0 00.228-1.024l-.98-2.178a1 1 0 00-1.316-.59l-1.28.513a5.52 5.52 0 00-1.518-.878l-.264-1.325zM10 8a2 2 0 110 4 2 2 0 010-4z" />
    </svg>
  </button>

  <button
    onclick="document.getElementById('logout-form').submit();"
    class="fixed top-6 right-6 bg-black text-white px-6 py-2 rounded-lg font-medium z-40 hover:bg-gray-800">
    Log out
  </button>

  <!-- メイン -->
  <div class="max-w-2xl mx-auto pt-24 pb-24 px-4">
    <div class="bg-white rounded-3xl shadow-md p-6 mb-6">
      <h2 class="text-2xl font-bold mb-4">設定</h2>

      <!-- 設定項目：今はユーザー情報だけ -->
      <div class="space-y-3">
        <button
          type="button"
          onclick="document.getElementById('user-info-panel').classList.remove('hidden')"
          class="w-full flex items-center justify-between px-4 py-3 rounded-2xl border border-gray-200 hover:bg-gray-50">
          <span class="font-medium">ユーザー情報</span>
          <span class="text-gray-400">&gt;</span>
        </button>
      </div>
    </div>

    <!-- ユーザー情報編集パネル -->
    <div id="user-info-panel" class="bg-white rounded-3xl shadow-md p-6 hidden">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-xl font-bold">ユーザー情報</h3>
        <button
          type="button"
          onclick="document.getElementById('user-info-panel').classList.add('hidden')"
          class="text-gray-400 hover:text-gray-600 text-2xl leading-none">
          ×
        </button>
      </div>

      <form action="/settings/user" method="POST" class="space-y-4">
        <div>
          <label class="block text-sm font-medium mb-1">ユーザー名</label>
          <input
            type="text"
            name="username"
            value="${req.user.username || ''}"
            class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:outline-none focus:border-blue-500"
            required
          >
        </div>

        <div>
          <label class="block text-sm font-medium mb-1">ユーザーID（@から始まる）</label>
          <input
            type="text"
            name="handle"
            value="${req.user.handle || ''}"
            class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:outline-none focus:border-blue-500"
            required
          >
        </div>

        <button
          type="submit"
          class="w-full mt-2 bg-blue-500 text-white py-3 rounded-2xl font-semibold hover:bg-blue-600">
          保存する
        </button>
      </form>
    </div>
  </div>
</body>
</html>`);
});

// ユーザー情報更新（ユーザー名・ID）
app.post('/settings/user', async (req, res) => {
  if (!req.user) return res.redirect('/login-modal');

  try {
    let { username, handle } = req.body;

    if (!username || !username.trim()) {
      return res.send(`
        <script>
          alert("ユーザー名を入力してください");
          history.back();
        </script>
      `);
    }
    if (!handle || !handle.trim()) {
      return res.send(`
        <script>
          alert("ユーザーID（@）を入力してください");
          history.back();
        </script>
      `);
    }

    username = username.trim();
    handle = handle.trim();
    if (!handle.startsWith('@')) handle = '@' + handle;

    const { error } = await supabase
      .from('users')
      .update({ username, handle })
      .eq('id', req.user.id);

    if (error) {
      console.error('Update user info error:', error);
      if (error.code === '23505') {
        return res.send(`
          <script>
            alert("そのユーザー名またはユーザーID（@）はすでに使われています。別のものを入力してください。");
            history.back();
          </script>
        `);
      }
      return res.send(`
        <script>
          alert("ユーザー情報の更新中にエラーが発生しました: ${error.message}");
          history.back();
        </script>
      `);
    }

    return res.send(`
      <script>
        alert("ユーザー情報を更新しました");
        location.href = '/settings';
      </script>
    `);
  } catch (e) {
    console.error('POST /settings/user error:', e);
    return res.send(`
      <script>
        alert("ユーザー情報の更新中にサーバーエラーが発生しました");
        history.back();
      </script>
    `);
  }
});

// ホーム（検索付き・未ログインでも閲覧可）
app.get('/', async (req, res) => {
  const q = req.query.q || '';

  let query = supabase
    .from('posts')
    .select('*, users(username)')
    .order('time', { ascending: false });

  if (q) {
    query = query.ilike('text', `%${q}%`);
  }

  const { data: postsData, error } = await query;

  if (error) {
    console.error('Supabase posts error:', error);
  }

  const posts = postsData || [];
  const isLoggedIn = !!req.user;

  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>sententia</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">

  <!-- 左上タイトル + プロフィールアイコン -->
  <div class="fixed top-6 left-6 z-40 flex items-center gap-4">
    <h1 class="text-3xl font-bold text-indigo-600 cursor-pointer" onclick="location.href='/'">
      sententia
    </h1>

    <!-- 水色オリジナルアイコン（ログイン時はプロフィールへ、未ログイン時はログインへ） -->
    <button
      onclick="${
        isLoggedIn
          ? "location.href='/profile';"
          : "location.href='/login-modal';"
      }"
      class="w-10 h-10 rounded-full bg-gradient-to-br from-sky-400 to-cyan-500 flex items-center justify-center shadow-md overflow-hidden"
    >
      <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" class="w-7 h-7">
        <circle cx="12" cy="8" r="4" fill="#e0f2fe"/>
        <path d="M4 19c1.2-3.2 4-5 8-5s6.8 1.8 8 5" fill="#bae6fd" />
      </svg>
    </button>
  </div>

  <!-- 右上 設定アイコン + Log in/out -->
  <form id="logout-form" action="/logout" method="POST" style="display:none;"></form>

  <button
    onclick="${
      isLoggedIn
        ? "location.href='/settings';"
        : "location.href='/login-modal';"
    }"
    class="fixed top-6 right-20 bg-white border border-gray-300 text-gray-700 px-3 py-2 rounded-full font-medium z-40 hover:bg-gray-50 flex items-center justify-center shadow-sm">
    <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" viewBox="0 0 20 20" fill="currentColor">
      <path d="M11.983 1.904a1 1 0 00-1.966 0l-.264 1.325a5.52 5.52 0 00-1.518.878l-1.28-.513a1 1 0 00-1.316.59L3.66 6.362a1 1 0 00.228 1.024l.94.94a5.52 5.52 0 000 1.748l-.94.94a1 1 0 00-.228 1.024l.98 2.178a1 1 0 001.316.59l1.28-.513c.46.37.968.673 1.518.878l.264 1.325a1 1 0 001.966 0l.264-1.325a5.52 5.52 0 001.518-.878l1.28.513a1 1 0 001.316-.59l.98-2.178a1 1 0 00-.228-1.024l-.94-.94a5.52 5.52 0 000-1.748l.94-.94a1 1 0 00.228-1.024l-.98-2.178a1 1 0 00-1.316-.59l-1.28.513a5.52 5.52 0 00-1.518-.878l-.264-1.325zM10 8a2 2 0 110 4 2 2 0 010-4z" />
    </svg>
  </button>

  <button
    onclick="${
      isLoggedIn
        ? "document.getElementById('logout-form').submit();"
        : "location.href='/login-modal';"
    }"
    class="fixed top-6 right-6 bg-black text-white px-6 py-2 rounded-lg font-medium z-40 hover:bg-gray-800">
    ${isLoggedIn ? 'Log out' : 'Log in'}
  </button>

  <div class="max-w-2xl mx-auto pt-24 pb-32 px-4">

    <!-- 検索フォーム -->
    <form action="/" method="GET" class="relative mb-8">
      <input
        type="text"
        name="q"
        value="${q ? q.replace(/"/g, '&quot;') : ''}"
        placeholder="キーワードで検索"
        class="w-full pl-12 pr-6 py-4 text-lg rounded-full border border-gray-300 focus:outline-none focus:border-indigo-500">
      <svg class="absolute left-4 top-5 w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
      </svg>
    </form>

    ${
      q
        ? `<p class="text-sm text-gray-500 mb-4">「${q}」の検索結果：${posts.length}件</p>`
        : ''
    }

    <h2 class="text-2xl font-bold mb-6">最近のトピック</h2>
    <div class="space-y-4">
      ${posts
        .map(
          (p) => `
        <div class="bg-white rounded-2xl p-6 shadow-md">
          <div class="flex items-center gap-3 mb-2">
            <span class="px-4 py-1 rounded-full text-sm font-medium ${
              p.type === 'company'
                ? 'bg-blue-100 text-blue-700'
                : 'bg-purple-100 text-purple-700'
            }">
              ${p.type === 'company' ? '企業' : '物事'}
            </span>
            <span class="text-gray-500 text-sm">
              ${
                p.time
                  ? new Date(p.time).toLocaleString('ja-JP', {
                      hour: '2-digit',
                      minute: '2-digit'
                    })
                  : ''
              }
            </span>
          </div>
          <div class="flex items-start gap-3">
            <span class="text-sm font-medium text-gray-700 mt-1">${
              p.users?.username || '匿名'
            }</span>
            <p class="text-lg flex-1">${p.text}</p>
          </div>
        </div>
      `
        )
        .join('')}
    </div>
  </div>

  <!-- 投稿ボタン -->
  <button
    onclick="${
      isLoggedIn
        ? "document.getElementById('modal').classList.remove('hidden');"
        : "location.href='/login-modal';"
    }"
    class="fixed bottom-6 right-6 w-44 h-14 bg-blue-500 hover:bg-blue-600 text-white rounded-full shadow-2xl flex items-center justify-center text-xl font-bold z-[100] transition-all hover:scale-105">
    投稿する
  </button>

  <!-- 投稿モーダル -->
  <div id="modal" class="hidden fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50">
    <div class="bg-white rounded-3xl shadow-2xl w-full max-w-lg mx-4 p-8 relative">
      <button onclick="document.getElementById('modal').classList.add('hidden')"
              class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-3xl">×</button>

      <form action="/post" method="POST">
        <div class="mb-8">
          <button type="button" onclick="this.nextElementSibling.classList.toggle('hidden')"
                  class="w-full text-left text-xl font-medium flex items-center justify-between bg-gray-100 px-6 py-4 rounded-2xl">
            <span id="selected-type">企業</span>
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
          </button>
          <div class="hidden mt-2 bg-white rounded-2xl shadow-lg overflow-hidden">
            <label class="block px-6 py-4 hover:bg-gray-50 cursor-pointer">
              <input type="radio" name="type" value="company" checked onchange="document.getElementById('selected-type').textContent='企業'" class="hidden">
              企業
            </label>
            <label class="block px-6 py-4 hover:bg-gray-50 cursor-pointer">
              <input type="radio" name="type" value="thing" onchange="document.getElementById('selected-type').textContent='物事'" class="hidden">
              物事
            </label>
          </div>
        </div>

        <textarea name="opinion" placeholder="意見を入力" required
                  class="w-full h-48 p-5 text-lg border-2 border-gray-200 rounded-2xl focus:border-blue-500 focus:outline-none resize-none mb-20"></textarea>

        <button type="submit"
                class="absolute bottom-6 right-6 bg-blue-500 hover:bg-blue-600 text-white font-bold py-4 px-8 rounded-full shadow-lg transition-all hover:scale-105">
          送信
        </button>
      </form>
    </div>
  </div>

</body>
</html>`);
});

// ログアウト
app.post('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
  });
  res.redirect('/login-modal');
});

// 投稿エンドポイント（ログイン必須）
app.post('/post', async (req, res) => {
  if (!req.user) return res.redirect('/login-modal');
  const { error } = await supabase.from('posts').insert({
    user_id: req.user.id,
    type: req.body.type || 'company',
    text: req.body.opinion
  });
  if (error)
    return res.send(
      '<script>alert("投稿エラー: ' +
        error.message +
        '"); history.back();</script>'
    );
  res.send(`
    <script>
      alert('投稿完了！');
      location.href = '/';
    </script>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('sententia起動中', PORT));
