const express = require('express');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// IPごとのユーザー管理（Map: IP → {user, password}）
const sessions = new Map(); // IPをキー、ログイン状態を値に

let posts = []; // ユーザーの投稿を記憶

app.get('/login-modal', (req, res) => {
  const ip = req.ip;
  res.send(`
    <!DOCTYPE html>
    <html lang="ja">
    <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Login - sententia</title><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-gray-100 min-h-screen flex items-center justify-center">
      <div class="bg-white rounded-3xl shadow-2xl p-8 w-full max-w-lg relative">
        <button onclick="location.href='/'" class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-3xl">×</button>
        <h2 class="text-2xl font-bold text-center mb-6">ログインする</h2>
        <form action="/login" method="POST">
          <input type="text" name="username" placeholder="ユーザー名" required class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-4 focus:outline-none focus:border-blue-500">
          <input type="password" name="password" placeholder="パスワード" required class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-6 focus:outline-none focus:border-blue-500">
          <button type="submit" class="w-full bg-blue-500 text-white py-3 rounded-2xl font-semibold hover:bg-blue-600 mb-6">ログイン</button>
        </form>
        <p class="text-center text-gray-500">アカウントをお持ちでないですか？ <a href="/signup" class="text-blue-500 hover:text-blue-700 font-medium">Sign up</a></p>
      </div>
    </body>
    </html>
  `);
});

app.get('/signup', (req, res) => {
  const ip = req.ip;
  res.send(`
    <!DOCTYPE html>
    <html lang="ja">
    <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Sign up - sententia</title><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-gray-100 min-h-screen flex items-center justify-center">
      <div class="bg-white rounded-3xl shadow-2xl p-8 w-full max-w-lg relative">
        <button onclick="location.href='/'" class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-3xl">×</button>
        <h2 class="text-2xl font-bold text-center mb-6">アカウントを作成</h2>
        <form action="/signup" method="POST">
          <input type="text" name="username" placeholder="ユーザー名" required class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-4 focus:outline-none focus:border-blue-500">
          <input type="password" name="password" placeholder="パスワード" required class="w-full px-4 py-3 border border-gray-300 rounded-2xl mb-6 focus:outline-none focus:border-blue-500">
          <button type="submit" class="w-full bg-blue-500 text-white py-3 rounded-2xl font-semibold hover:bg-blue-600">作成する</button>
        </form>
        <p class="text-center text-gray-500 mt-4 cursor-pointer hover:text-blue-500" onclick="location.href='/login-modal'">すでにアカウントをお持ちですか？ Log in</p>
      </div>
    </body>
    </html>
  `);
});

app.post('/signup', (req, res) => {
  const ip = req.ip;
  const { username, password } = req.body;
  if (sessions.get(ip)?.user === username) {
    res.send('<script>alert("ユーザー名が既に存在します"); history.back();</script>');
  } else {
    sessions.set(ip, { user: username, password });
    res.redirect('/');
  }
});

app.get('/', (req, res) => {
  const ip = req.ip;
  const session = sessions.get(ip);
  if (!session) return res.redirect('/login-modal');

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

  <!-- 左上タイトル -->
  <div class="fixed top-6 left-6 z-40">
    <h1 class="text-3xl font-bold text-indigo-600">sententia</h1>
  </div>

  <!-- 右上 Log out ボタン -->
  <form action="/logout" method="POST" style="display: inline;">
    <button type="submit" class="fixed top-6 right-6 bg-black text-white px-6 py-2 rounded-lg font-medium z-40 hover:bg-gray-800">
      Log out
    </button>
  </form>

  <!-- メインコンテンツ -->
  <div class="max-w-2xl mx-auto pt-24 pb-32 px-4">

    <!-- 検索ボックス -->
    <div class="relative mb-8">
      <input type="text" placeholder="キーワードで検索" class="w-full pl-12 pr-6 py-4 text-lg rounded-full border border-gray-300 focus:outline-none focus:border-indigo-500">
      <svg class="absolute left-4 top-5 w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
      </svg>
    </div>

    <!-- 最近のトピック -->
    <h2 class="text-2xl font-bold mb-6">最近のトピック</h2>
    <div class="space-y-4">
      ${posts.map(p => `
        <div class="bg-white rounded-2xl p-6 shadow-md">
          <div class="flex items-center gap-3 mb-2">
            <span class="px-4 py-1 rounded-full text-sm font-medium ${p.type==='company'?'bg-blue-100 text-blue-700':'bg-purple-100 text-purple-700'}">
              ${p.type==='company'?'企業':'物事'}
            </span>
            <span class="text-gray-500 text-sm">${p.time}</span>
          </div>
          <div class="flex items-start gap-3">
            <span class="text-sm font-medium text-gray-700 mt-1">${p.user}</span>
            <p class="text-lg flex-1">${p.text}</p>
          </div>
        </div>
      `).join('')}
    </div>
  </div>

  <!-- 投稿ボタン（z-index強化） -->
  <button onclick="document.getElementById('modal').classList.remove('hidden')"
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
</html>
  `);
});

app.post('/login', (req, res) => {
  const ip = req.ip;
  const { username, password } = req.body;
  if (sessions.get(ip)?.user === username && sessions.get(ip)?.password === password) {
    res.redirect('/');
  } else {
    res.send('<script>alert("ユーザー名かパスワードが間違っています"); location.href="/login-modal";</script>');
  }
});

app.post('/logout', (req, res) => {
  const ip = req.ip;
  sessions.delete(ip);
  res.redirect('/login-modal');
});

app.post('/post', (req, res) => {
  const ip = req.ip;
  const session = sessions.get(ip);
  if (!session) return res.redirect('/login-modal');
  posts.unshift({
    user: session.user,
    type: req.body.type || "company",
    text: req.body.opinion,
    time: "たった今"
  });
  res.send(`
    <script>
      alert('投稿完了！');
      location.href = '/';
    </script>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('sententia起動中', PORT));
