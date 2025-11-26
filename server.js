// server.js

const express = require('express');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const Redis = require('ioredis');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
        // 既存ユーザー確認
        let { data: user, error } = await supabase
          .from('users')
          .select('*')
          .eq('google_id', profile.id)
          .single();

        if (error && error.code !== 'PGRST116') {
          // 予期せぬエラー
          return done(error);
        }

        if (!user) {
          // 新規ユーザー作成
          const email =
            profile.emails && profile.emails[0]
              ? profile.emails[0].value
              : null;

          const baseName =
            profile.displayName ||
            (email ? email.split('@')[0] : `user_${Date.now()}`);

          // handle は "@xxx" 形式、20文字制限
          let handle = '@' + baseName.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
          if (handle.length > 20) handle = handle.slice(0, 20);

          const { data: inserted, error: insertError } = await supabase
            .from('users')
            .insert({
              google_id: profile.id,
              username: baseName.slice(0, 20), // 念のため 20 文字制限
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
  done(null, user.id); // users.id (uuid)
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

// ログインチェック用ミドルウェア
function ensureAuthenticated(req, res, next) {
  if (req.user) return next();
  return res.redirect('/login-modal');
}

// =============================
// OAuthルート
// =============================
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login-modal' }),
  (req, res) => res.redirect('/')
);

// =============================
// ログイン / サインアップ画面
// =============================

// ログインモーダル（背景暗く・×でホームへ）
app.get('/login-modal', async (req, res) => {
  // ホームの投稿も読み込んで、背景にうっすら出すイメージ（簡易版）
  const { data: postsData } = await supabase
    .from('posts')
    .select('id, user_id, type, text, time, parent_post_id, users(username, handle)')
    .order('time', { ascending: false });

  const posts = postsData || [];

  res.send(`
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>Login - sententia</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen relative">

  <!-- 背景としてホーム（簡略版） -->
  <div class="pointer-events-none opacity-40">
    <div class="max-w-2xl mx-auto pt-24 pb-32 px-4">
      <h1 class="text-3xl font-bold text-indigo-600 mb-6">sententia</h1>
      <div class="space-y-4">
        ${posts
          .map(
            (p) => `
          <div class="bg-white rounded-2xl p-4 shadow-sm">
            <div class="flex items-start gap-3">
              <div class="w-10 h-10 rounded-full flex items-center justify-center bg-blue-100">
                <span class="text-xl">👤</span>
              </div>
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
                <p class="mt-2 text-sm break-words">${p.text}</p>
              </div>
            </div>
          </div>
        `
          )
          .join('')}
      </div>
    </div>
  </div>

  <!-- 黒いオーバーレイ -->
  <div class="absolute inset-0 bg-black bg-opacity-60 z-0"></div>

  <!-- 中央のログインカード -->
  <div class="absolute inset-0 flex items-center justify-center z-10">
    <div class="bg-white rounded-3xl shadow-2xl p-8 w-full max-w-lg relative">
      <button onclick="location.href='/'"
              class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-3xl">×</button>
      <h2 class="text-2xl font-bold text-center mb-6">ログインする</h2>

      <!-- ユーザー名＋パスワードのログイン（必要ならここに後で実装） -->
      <form action="/login" method="POST" class="mb-4">
        <input type="text" name="username" placeholder="ユーザー名"
               maxlength="20"
               required
               class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-3 focus:outline-none focus:border-blue-500">
        <input type="password" name="password" placeholder="パスワード"
               required
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
  <title>Sign up - sententia</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center">
  <div class="bg-white rounded-3xl shadow-2xl p-8 w-full max-w-lg relative">
    <button onclick="location.href='/'"
            class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-3xl">×</button>
    <h2 class="text-2xl font-bold text-center mb-6">アカウントを作成</h2>
    <form action="/signup" method="POST">
      <input type="text" name="username" placeholder="ユーザー名"
             maxlength="20"
             required
             class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-4 focus:outline-none focus:border-blue-500">
      <input type="password" name="password" placeholder="パスワード"
             required
             class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-4 focus:outline-none focus:border-blue-500">
      <input type="text" name="handle" placeholder="@ユーザーID（任意）"
             maxlength="20"
             class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-6 focus:outline-none focus:border-blue-500">
      <button type="submit"
              class="w-full bg-blue-500 text-white py-3 rounded-2xl font-semibold hover:bg-blue-600">
        作成する
      </button>
    </form>
    <p class="text-center text-gray-500 mt-4 cursor-pointer hover:text-blue-500"
       onclick="location.href='/login-modal'">
      すでにアカウントをお持ちですか？ Log in
    </p>
  </div>
</body>
</html>
  `);
});

// サインアップ処理（ローカルアカウント）
app.post('/signup', async (req, res) => {
  try {
    const { username, password, handle } = req.body;

    if (!username || username.length > 20) {
      return res.send(
        `<script>alert("ユーザー名は1〜20文字で入力してください。"); history.back();</script>`
      );
    }

    let finalHandle = handle?.trim();
    if (finalHandle) {
      if (!finalHandle.startsWith('@')) finalHandle = '@' + finalHandle;
      if (finalHandle.length > 20) {
        return res.send(
          `<script>alert("ユーザーID（@〜）は20文字以内で入力してください。"); history.back();</script>`
        );
      }
    } else {
      finalHandle = null;
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from('users')
      .insert({
        username,
        password: hashedPassword,
        handle: finalHandle
      })
      .select()
      .single();

    if (error) {
      return res.send(
        `<script>alert("サインアップエラー: ${error.message}"); history.back();</script>`
      );
    }

    req.login(data, () => res.redirect('/'));
  } catch (err) {
    console.error('Supabase signup error:', err);
    return res.send(
      `<script>alert("予期せぬエラーが発生しました。"); history.back();</script>`
    );
  }
});

// ローカルログイン
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
        `<script>alert("ユーザー名またはパスワードが違います。"); history.back();</script>`
      );
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.send(
        `<script>alert("ユーザー名またはパスワードが違います。"); history.back();</script>`
      );
    }

    req.login(user, () => res.redirect('/'));
  } catch (err) {
    console.error('Login error:', err);
    return res.send(
      `<script>alert("ログイン中にエラーが発生しました。"); history.back();</script>`
    );
  }
});

// =============================
// 設定画面（ユーザー名/ID変更）
// =============================
app.get('/settings', ensureAuthenticated, (req, res) => {
  const user = req.user;
  res.send(`
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>設定 - sententia</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">

  <!-- 左上タイトル（クリックでホームに戻る） -->
  <div class="fixed top-6 left-6 z-40">
    <button onclick="location.href='/'" class="text-3xl font-bold text-indigo-600">
      sententia
    </button>
  </div>

  <!-- 右上 設定 & Log out -->
  <div class="fixed top-6 right-6 z-40 flex items-center gap-3">
    <button onclick="location.href='/settings'"
            class="w-10 h-10 rounded-full border bg-white flex items-center justify-center text-xl hover:bg-gray-50">
      ⚙️
    </button>
    <form action="/logout" method="POST">
      <button type="submit"
              class="bg-black text-white px-5 py-2 rounded-lg font-medium hover:bg-gray-800">
        Log out
      </button>
    </form>
  </div>

  <div class="max-w-xl mx-auto pt-28 pb-16 px-4">
    <h1 class="text-2xl font-bold mb-6">設定</h1>

    <!-- ユーザー情報セクション -->
    <div class="bg-white rounded-2xl shadow-md p-6 mb-4">
      <button onclick="document.getElementById('user-info-form').classList.toggle('hidden')"
              class="w-full flex items-center justify-between text-left">
        <span class="font-semibold text-lg">ユーザー情報</span>
        <span class="text-gray-400 text-xl">▼</span>
      </button>

      <form id="user-info-form" action="/settings/profile" method="POST" class="mt-4 hidden">
        <label class="block mb-3 text-sm text-gray-600">ユーザー名（20文字まで）</label>
        <input type="text" name="username" maxlength="20"
               value="${user.username || ''}"
               required
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
  </div>
</body>
</html>
  `);
});

app.post('/settings/profile', ensureAuthenticated, async (req, res) => {
  const { username, handle } = req.body;
  const userId = req.user.id;

  if (!username || username.length > 20) {
    return res.send(
      `<script>alert("ユーザー名は1〜20文字で入力してください。"); history.back();</script>`
    );
  }

  let finalHandle = handle?.trim();
  if (finalHandle) {
    if (!finalHandle.startsWith('@')) finalHandle = '@' + finalHandle;
    if (finalHandle.length > 20) {
      return res.send(
        `<script>alert("ユーザーID（@〜）は20文字以内で入力してください。"); history.back();</script>`
      );
    }
  } else {
    finalHandle = null;
  }

  const { error } = await supabase
    .from('users')
    .update({ username, handle: finalHandle })
    .eq('id', userId);

  if (error) {
    return res.send(
      `<script>alert("更新エラー: ${error.message}"); history.back();</script>`
    );
  }

  // セッションのユーザー情報を更新したいので再取得
  const { data: updatedUser } = await supabase
    .from('users')
    .select('*')
    .eq('id', userId)
    .single();

  req.login(updatedUser, () => {
    res.send(`<script>alert("更新しました。"); location.href='/settings';</script>`);
  });
});

// =============================
// ホーム + 投稿 / 返信 / いいね
// =============================

app.get('/', async (req, res) => {
  // 投稿取得
  const { data: postsData, error: postsError } = await supabase
    .from('posts')
    .select('id, user_id, type, text, time, parent_post_id, users(username, handle)')
    .order('time', { ascending: false });

  const posts = postsError || !postsData ? [] : postsData;

  // いいね情報取得
  let likesMap = {};
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
        if (req.user && like.user_id === req.user.id) {
          likesMap[like.post_id].likedByUser = true;
        }
      });
    }
  }

  // 親投稿と返信を分ける
  const topPosts = posts.filter((p) => !p.parent_post_id);
  const repliesByParent = {};
  posts
    .filter((p) => p.parent_post_id)
    .forEach((p) => {
      if (!repliesByParent[p.parent_post_id]) repliesByParent[p.parent_post_id] = [];
      repliesByParent[p.parent_post_id].push(p);
    });

  const user = req.user;

  res.send(`
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>sententia</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">

  <!-- 左上タイトル（クリックでホーム） -->
  <div class="fixed top-6 left-6 z-40">
    <button onclick="location.href='/'" class="text-3xl font-bold text-indigo-600">
      sententia
    </button>
  </div>

  <!-- 右上 設定 + Log in / Log out -->
  <div class="fixed top-6 right-6 z-40 flex items-center gap-3">
    ${
      user
        ? `
      <button onclick="location.href='/settings'"
              class="w-10 h-10 rounded-full border bg-white flex items-center justify-center text-xl hover:bg-gray-50">
        ⚙️
      </button>
      <form action="/logout" method="POST">
        <button type="submit"
                class="bg-black text-white px-5 py-2 rounded-lg font-medium hover:bg-gray-800">
          Log out
        </button>
      </form>
    `
        : `
      <button onclick="location.href='/login-modal'"
              class="bg-black text-white px-5 py-2 rounded-lg font-medium hover:bg-gray-800">
        Log in
      </button>
    `
    }
  </div>

  <!-- メインコンテンツ -->
  <div class="max-w-2xl mx-auto pt-24 pb-32 px-4">

    <!-- 検索ボックス（中身は今は未実装） -->
    <div class="relative mb-8">
      <input type="text" placeholder="キーワードで検索"
             class="w-full pl-12 pr-6 py-4 text-lg rounded-full border border-gray-300 focus:outline-none focus:border-indigo-500">
      <svg class="absolute left-4 top-5 w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
      </svg>
    </div>

    <!-- 最近のトピック -->
    <h2 class="text-2xl font-bold mb-6">最近のトピック</h2>
    <div class="space-y-4">
      ${
        topPosts.length === 0
          ? '<p class="text-gray-500">まだ投稿がありません。</p>'
          : topPosts
              .map((p) => {
                const likeInfo = likesMap[p.id] || { count: 0, likedByUser: false };
                const likeIcon = likeInfo.likedByUser ? '❤️' : '🤍';
                const replies = repliesByParent[p.id] || [];
                return `
        <div class="bg-white rounded-2xl p-4 shadow-md">
          <!-- 親投稿 -->
          <div class="flex items-start gap-3">
            <!-- アイコン（X風・水色） -->
            <div class="w-10 h-10 rounded-full flex items-center justify-center bg-blue-100">
              <!-- シンプルな人型アイコン -->
              <svg viewBox="0 0 24 24" class="w-6 h-6 text-blue-500" fill="currentColor">
                <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4S8 5.79 8 8s1.79 4 4 4zm0 2c-3.33 0-6 2.24-6 5v1h12v-1c0-2.76-2.67-5-6-5z"/>
              </svg>
            </div>

            <div class="flex-1">
              <!-- ヘッダー行 -->
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

              <!-- 本文 -->
              <p class="mt-2 text-sm whitespace-pre-wrap break-words">${p.text}</p>

              <!-- アクション（返信・いいね） -->
              <div class="mt-3 flex items-center gap-6 text-sm text-gray-500">
                <button type="button"
                        onclick="${
                          user
                            ? `openPostModal('${p.id}')`
                            : `location.href='/login-modal'`
                        }"
                        class="flex items-center gap-1 hover:text-blue-500">
                  💬<span>${replies.length}</span>
                </button>
                <button type="button"
                        onclick="${
                          user
                            ? `handleLike('${p.id}')`
                            : `location.href='/login-modal'`
                        }"
                        class="flex items-center gap-1 hover:text-pink-500">
                  <span>${likeIcon}</span><span>${likeInfo.count}</span>
                </button>
              </div>
            </div>
          </div>

          <!-- 返信一覧（簡易表示） -->
          ${
            replies.length > 0
              ? `
            <div class="mt-3 border-l pl-4 space-y-2">
              ${replies
                .map(
                  (r) => `
                <div class="flex items-start gap-2">
                  <div class="w-8 h-8 rounded-full flex items-center justify-center bg-blue-50">
                    <svg viewBox="0 0 24 24" class="w-5 h-5 text-blue-400" fill="currentColor">
                      <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4S8 5.79 8 8s1.79 4 4 4zm0 2c-3.33 0-6 2.24-6 5v1h12v-1c0-2.76-2.67-5-6-5z"/>
                    </svg>
                  </div>
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
              : ''
          }
        </div>
      `;
              })
              .join('')
      }
    </div>
  </div>

  <!-- 投稿ボタン -->
  <button onclick="${
    user
      ? "openPostModal('')"
      : "location.href='/login-modal'"
  }"
          class="fixed bottom-6 right-6 w-44 h-14 bg-blue-500 hover:bg-blue-600 text-white rounded-full shadow-2xl flex items-center justify-center text-xl font-bold z-[100] transition-all hover:scale-105">
    投稿する
  </button>

  <!-- 投稿 / 返信モーダル -->
  <div id="modal" class="hidden fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50">
    <div class="bg-white rounded-3xl shadow-2xl w-full max-w-lg mx-4 p-8 relative">
      <button onclick="closePostModal()"
              class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-3xl">×</button>

      <form action="/post" method="POST">
        <input type="hidden" name="parent_post_id" id="parent_post_id_input">

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
</html>
  `);
});

// ログアウト
app.post('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect('/login-modal');
  });
});

// 投稿 / 返信
app.post('/post', ensureAuthenticated, async (req, res) => {
  const { type, opinion, parent_post_id } = req.body;

  if (!opinion || opinion.length === 0 || opinion.length > 200) {
    return res.send(
      `<script>alert("投稿は1〜200文字で入力してください。"); history.back();</script>`
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
      `<script>alert("投稿エラー: ${error.message}"); history.back();</script>`
    );
  }

  res.send(`
    <script>
      alert('投稿完了！');
      location.href = '/';
    </script>
  `);
});

// いいねトグル
app.post('/like/:postId', ensureAuthenticated, async (req, res) => {
  const postId = req.params.postId;
  const userId = req.user.id;

  try {
    // 既にいいねしているか確認
    const { data: existing, error: selectError } = await supabase
      .from('likes')
      .select('id')
      .eq('user_id', userId)
      .eq('post_id', postId)
      .maybeSingle();

    if (selectError && selectError.code !== 'PGRST116') {
      console.error('like select error', selectError);
      return res.status(500).send('error');
    }

    if (existing) {
      // いいね解除
      const { error: deleteError } = await supabase
        .from('likes')
        .delete()
        .eq('id', existing.id);
      if (deleteError) {
        console.error('like delete error', deleteError);
        return res.status(500).send('error');
      }
    } else {
      // いいね追加
      const { error: insertError } = await supabase
        .from('likes')
        .insert({ user_id: userId, post_id: postId });
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
