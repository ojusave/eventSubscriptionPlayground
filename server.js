const {app,server,PORT,path,crypto,WebSocket} = require('./config/config');

const middleware = require('./middleware/middleware');

middleware(app);

const io = require('./services/socketio')


// Middleware Setup

const { webhookRoutes } = require('./routes/webhookRoutes');
webhookRoutes(app);

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


const { client, clearRedisCache } = require('./services/redis');




server.listen(PORT, () => {

    clearRedisCache()
    console.log(`Server is running on http://localhost:${PORT}`);
});
