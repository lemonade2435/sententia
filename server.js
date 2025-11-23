const express = require('express');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>sententia</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 min-h-screen">

  <!-- 左上タイトル -->
  <div class="fixed top-6 left-6 z-40">
    <h1 class="text-3xl font-bold text-indigo-600">sententia</h1>
  </div>

  <!-- 投稿一覧（今は空でもOK、後で追加） -->
  <div class="max-w-2xl mx-auto pt-24 pb-32">
    <!-- ここに後で投稿が並ぶ -->
  </div>

  <!-- 右下固定ボタン -->
  <button onclick="document.getElementById('modal').classList.remove('hidden')"
          class="fixed bottom-6 right-6 w-14 h-14 bg-blue-500 hover:bg-blue-600 text-white rounded-full shadow-2xl flex items-center justify-center text-4xl font-bold z-50 transition-all hover:scale-110">
    +
  </button>

  <!-- モーダル（最初は非表示） -->
  <div id="modal" class="hidden fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50">
    <div class="bg-white rounded-3xl shadow-2xl w-full max-w-lg mx-4 p-8 relative">
      
      <!-- 閉じるボタン -->
      <button onclick="document.getElementById('modal').classList.add('hidden')"
              class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-3xl">×</button>

      <form action="/post" method="POST">
        <!-- 企業 / 物事 タブ -->
        <div class="flex gap-3 mb-6">
          <input type="radio" name="type" value="company" id="company" checked class="hidden peer/company">
          <label for="company" class="bg-blue-600 text-white px-6 py-3 rounded-xl font-medium cursor-pointer peer-checked/company:bg-blue-600">企業</label>
          
          <input type="radio" name="type" value="thing" id="thing" class="hidden peer/thing">
          <label for="thing" class="bg-gray-100 text-gray-600 px-6 py-3 rounded-xl font-medium cursor-pointer hover:bg-gray-200 peer-checked/thing:bg-blue-600 peer-checked/thing:text-white">物事</label>
        </div>

        <!-- 意見入力 -->
        <textarea name="opinion" placeholder="意見を入力" required
                  class="w-full h-48 p-5 text-lg border-2 border-gray-200 rounded-2xl focus:border-blue-500 focus:outline-none resize-none"></textarea>

        <!-- 送信ボタン -->
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

app.post('/post', (req, res) => {
  console.log('新投稿 →', req.body);
  res.send(`
    <script>
      alert('投稿ありがとう！');
      location.href = '/';
    </script>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('sententia起動中', PORT));
