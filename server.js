const express = require('express');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
  res.send(`
    <h1>sententia</h1>
    <form action="/post" method="POST">
      <input name="company" placeholder="企業名" required><br><br>
      <textarea name="opinion" placeholder="意見を入力" rows="6" required></textarea><br><br>
      <button type="submit">投稿</button>
    </form>
  `);
});

app.post('/post', (req, res) => {
  console.log('投稿 →', req.body);
  res.send('<h2>投稿完了！</h2><a href="/">戻る</a>');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('起動', PORT));
