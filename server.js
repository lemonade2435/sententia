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

// Render 等のプロキシ環境だとセッション維持に必要
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
      secure: false, // デバッグ優先。https 本番では true にする
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

// プロフィール完成チェック用ヘルパー
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
    // Googleログイン後もプロフィールチェック
    if (needsOnboarding(req.user)) {
      return res.redirect('/onboarding');
    }
    return res.redirect('/');
  }
);

// ログイン画面
app.get('/login-modal', (req, res) => {
  if (req.user) return res.redirect('/');

  res.send(`
    <!DOCTYPE html>
    <html lang="ja">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Login - sententia</title>
      <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-100 min-h-screen flex items-center justify-center relative">
      <div class="absolute inset-0 z-0">
        <div class="fixed top-6 left-6">
          <h1 class="text-3xl font-bold text-indigo-600">sententia</h1>
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
    </html>
  `);
});

// サインアップ画面
app.get('/signup', (req, res) => {
  res.send(`
    <!DOCTYPE html>
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
    </html>
  `);
});

// ローカルサインアップ（ユーザー作成）
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

    // 作成後は通常のログイン画面へ
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
app.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    const { data: user, error } = await supabase
      .from('users')
      .select('id, username, password, birthday, gender, handle, tos_agreed_at, privacy_agreed_at')
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

// 追加情報登録画面（オンボーディング）
app.get('/onboarding', (req, res) => {
  if (!req.user) return res.redirect('/login-modal');

  res.send(`
    <!DOCTYPE html>
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
            <input type="date" name="birthday"
              class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:outline-none focus:border-blue-500" required>
          </div>

          <div>
            <label class="block text-sm font-medium mb-1">性別</label>
            <select name="gender"
              class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:outline-none focus:border-blue-500" required>
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
              class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:outline-none focus:border-blue-500" required>
          </div>

          <div class="space-y-2 text-sm">
            <label class="flex items-center gap-2">
              <input type="checkbox" name="agree_tos" required>
              <span>利用規約に同意します</span>
            </label>
            <label class="flex items-center gap-2">
              <input type="checkbox" name="agree_privacy" required>
              <span>プライバシーポリシーに同意します</span>
            </label>
          </div>

          <button type="submit"
            class="w-full mt-4 bg-blue-500 text-white py-3 rounded-2xl font-semibold hover:bg-blue-600">
            登録する
          </button>
        </form>
      </div>
    </body>
    </html>
  `);
});

// オンボーディング POST
app.post('/onboarding', async (req, res) => {
  if (!req.user) return res.redirect('/login-modal');

  try {
    let { birthday, gender, handle, agree_tos, agree_privacy } = req.body;

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

// ホーム（未ログインでも閲覧可）
app.get('/', async (req, res) => {
  const { data: postsData, error } = await supabase
    .from('posts')
    .select('*, users(username)')
    .order('time', { ascending: false });

  if (error) {
    console.error('Supabase posts error:', error);
  }

  const posts = postsData || [];
  const isLoggedIn = !!req.user;

  res.send(`
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>sententia</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">

  <div class="fixed top-6 left-6 z-40">
    <h1 class="text-3xl font-bold text-indigo-600">sententia</h1>
  </div>

  <form id="logout-form" action="/logout" method="POST" style="display:none;"></form>
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

    <div class="relative mb-8">
      <input type="text" placeholder="キーワードで検索" class="w-full pl-12 pr-6 py-4 text-lg rounded-full border border-gray-300 focus:outline-none focus:border-indigo-500">
      <svg class="absolute left-4 top-5 w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
      </svg>
    </div>

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

  <button
    onclick="${
      isLoggedIn
        ? "document.getElementById('modal').classList.remove('hidden');"
        : "location.href='/login-modal';"
    }"
    class="fixed bottom-6 right-6 w-44 h-14 bg-blue-500 hover:bg-blue-600 text-white rounded-full shadow-2xl flex items-center justify-center text-xl font-bold z-[100] transition-all hover:scale-105">
    投稿する
  </button>

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
</html>
  `);
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
  const { data, error } = await supabase.from('posts').insert({
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
