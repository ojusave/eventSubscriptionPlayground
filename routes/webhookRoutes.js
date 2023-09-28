const { baseURL, path, crypto, axios, WebSocket } = require('../config/config');
const {
    defaultHeaders,
    basicAuth,
    customHeaderAuth,
    webhookOAuth,
    tokenAuth,
    sendData
} = require('../utils/utils');
const { client } = require('../services/redis');
const io = require('../services/socketio');


const zoomWebSocketMap = new Map();
const subscriptionEndpointMap = new Map();
let currentAccess_token;
let activeEndpoints = new Set();

module.exports.webhookRoutes = (app) => {
    app.post('/configure-webhook', (req, res) => {
        //const { type, clientId, clientSecret, accountId, subscriptionId } = req.body;
        const newEndpoint = `${baseURL}/webhook-endpoint/${crypto.randomBytes(10).toString('hex')}`;
        req.session.endpoint = newEndpoint;
        activeEndpoints.add(newEndpoint);
        const endpointData = {
            config: req.body,
            tokens: [],
            events: []
        };
    
    
    
        if (req.body.type === 'token') {
            const oauthEndpoint = `${baseURL}/webhook-endpoint/oauth`;
            const oauthData = {
                clientId: req.body.clientId,
                clientSecret: req.body.clientSecret,
                secretToken: req.body.secretToken
            };
    
            // Store the clientId and clientSecret in a hash. If the clientId already exists, its value will be updated.
            client.hset(oauthEndpoint, oauthData.clientId, oauthData.clientSecret, (err) => {
                if (err) {
                    console.error('Error storing OAuth config in Redis:', err);
                    return res.status(500).send('Internal Server Error');
                }
            });
        }
    
    
        client.set(newEndpoint, JSON.stringify(endpointData), async (err) => {
            if (err) {
                console.error('Error storing in Redis:', err);
                return res.status(500).send('Internal Server Error');
            }
    
            client.expire(newEndpoint, 300);  // Set expiration for the key
    
    
            if (req.body.type === 'websocket') {
                try {
                    // Generate access token
                    const authString = Buffer.from(`${req.body.clientId}:${req.body.clientSecret}`).toString('base64');
                    const response = await axios.post(`https://zoom.us/oauth/token?grant_type=account_credentials&account_id=${req.body.accountId}`, {}, {
                        headers: {
                            Authorization: 'Basic ' + authString
                        }
                    });
    
                    const access_token = response.data.access_token;
                    subscriptionEndpointMap.set(req.body.subscriptionId, newEndpoint.split('/').pop());
                    // Use the generated access token to open the WebSocket connection
                    handleWebSocketConnection(req.body.subscriptionId, access_token);
                } catch (error) {
                    console.error("Error generating access token or opening WebSocket connection:", error);
                    return res.status(500).send('Internal Server Error');
                }
            }
    
            console.log('Received Configuration:', req.body);
            console.log('Generated Endpoint URL:', newEndpoint);
            activeEndpoints.add(newEndpoint);
            res.json({ endpointURL: newEndpoint });
        });
    });

    app.post('/webhook-endpoint/oauth', webhookOAuth);

    app.post('/configure-webhook', (req, res) => {
        //const { type, clientId, clientSecret, accountId, subscriptionId } = req.body;
        const newEndpoint = `${baseURL}/webhook-endpoint/${crypto.randomBytes(10).toString('hex')}`;
        req.session.endpoint = newEndpoint;
        activeEndpoints.add(newEndpoint);
        const endpointData = {
            config: req.body,
            tokens: [],
            events: []
        };
    
    
    
        if (req.body.type === 'token') {
            const oauthEndpoint = `${baseURL}/webhook-endpoint/oauth`;
            const oauthData = {
                clientId: req.body.clientId,
                clientSecret: req.body.clientSecret,
                secretToken: req.body.secretToken
            };
    
            // Store the clientId and clientSecret in a hash. If the clientId already exists, its value will be updated.
            client.hset(oauthEndpoint, oauthData.clientId, oauthData.clientSecret, (err) => {
                if (err) {
                    console.error('Error storing OAuth config in Redis:', err);
                    return res.status(500).send('Internal Server Error');
                }
            });
        }
    
    
        client.set(newEndpoint, JSON.stringify(endpointData), async (err) => {
            if (err) {
                console.error('Error storing in Redis:', err);
                return res.status(500).send('Internal Server Error');
            }
    
            client.expire(newEndpoint, 300);  // Set expiration for the key
    
    
            if (req.body.type === 'websocket') {
                try {
                    // Generate access token
                    const authString = Buffer.from(`${req.body.clientId}:${req.body.clientSecret}`).toString('base64');
                    const response = await axios.post(`https://zoom.us/oauth/token?grant_type=account_credentials&account_id=${req.body.accountId}`, {}, {
                        headers: {
                            Authorization: 'Basic ' + authString
                        }
                    });
    
                    const access_token = response.data.access_token;
                    subscriptionEndpointMap.set(req.body.subscriptionId, newEndpoint.split('/').pop());
                    // Use the generated access token to open the WebSocket connection
                    handleWebSocketConnection(req.body.subscriptionId, access_token);
                } catch (error) {
                    console.error("Error generating access token or opening WebSocket connection:", error);
                    return res.status(500).send('Internal Server Error');
                }
            }
    
            console.log('Received Configuration:', req.body);
            console.log('Generated Endpoint URL:', newEndpoint);
            activeEndpoints.add(newEndpoint);
            res.json({ endpointURL: newEndpoint });
        });
    });
    app.post('/webhook-endpoint/oauth', webhookOAuth);
    
    app.get('/webhook-endpoint/:id', (req, res) => {
        const endpointURL = `${baseURL}/webhook-endpoint/${req.params.id}`;
    
        if (req.session.endpoint !== endpointURL) {
            return res.status(400).send('Bad Request');
        }
        res.sendFile(path.join(__dirname, '../public/events.html'));
    });
    app.post('/webhook-endpoint/:id', handleWebhook);
    function handleWebhook(req, res) {
        const endpointId = req.params.id;
        const endpointURL = `${baseURL}/webhook-endpoint/${endpointId}`;
    
        client.get(endpointURL, (err, result) => {
    
            client.ttl(endpointURL, (err, ttl) => {
    
                if (err || ttl <= 0) {
                    console.error('Error fetching from Redis:', err);
                    return res.status(500).send('Internal Server Error');
                }
    
                if (!result) {
                    console.error("No data found in Redis for endpoint:", endpointURL);
                    return res.status(404).send("Data not found");
                }
                const endpointData = JSON.parse(result);
    
                // Storing the event data in Redis
                endpointData.events.push(req.body);
    
                // Saving updated data back to Redis
                client.set(endpointURL, JSON.stringify(endpointData), (err) => {
                    if (err) {
                        console.error('Error updating events in Redis:', err);
                    }
    
                    client.expire(endpointURL, ttl);
                });
    
                if (req.body.event === 'endpoint.url_validation') {
                    const hashForValidate = crypto.createHmac('sha256', endpointData.config.secretToken)
                        .update(req.body.payload.plainToken)
                        .digest('hex');
                    console.log('Webhook received from Zoom:', req.body);
                    console.log('Headers:', req.headers);
                    io.to(endpointId).emit('webhookData', sendData(req, activeEndpoints));
    
                    return res.status(200).json({
                        plainToken: req.body.payload.plainToken,
                        encryptedToken: hashForValidate
                    });
                }
    
                else if (!result) {
                    console.error("No data found in Redis for endpoint:", endpointURL);
                    return res.status(404).send("Data not found");
                }
    
                switch (endpointData.config.type) {
                    case 'token':
                        tokenAuth(req, res, endpointData);
                        break;
                    case 'none':
                        defaultHeaders(req, res, endpointData);
                        break;
                    case 'basic':
                        basicAuth(req, res, endpointData);
                        break;
                    case 'custom':
                        customHeaderAuth(req, res, endpointData);
                        break;
    
                    case 'websocket':
                        handleWebSocketConnection(endpointData.config.subscriptionID, currentAccess_token, endpointId);
                        break;
    
                }
            });
        });
    }

    function handleWebSocketConnection(subscriptionID, access_token, endpointId) {

        const webSocketUrl = `wss://ws.zoom.us/ws?subscriptionId=${subscriptionID}&access_token=${access_token}`;
        //const endpointId = req.params.id;
    
        console.log("[Zoom WebSocket] URL:", webSocketUrl);
    
        const zoomWebSocket = new WebSocket(webSocketUrl);
        zoomWebSocketMap.set(subscriptionID, zoomWebSocket);
    
        zoomWebSocket.on('open', () => {
            console.log("[Zoom WebSocket] Connected to WebSocket");
    
            const heartbeatMessage = {
                module: "heartbeat"
            };
    
            setInterval(() => {
                zoomWebSocket.send(JSON.stringify(heartbeatMessage));
                console.log('[Zoom WebSocket] Heartbeat sent', heartbeatMessage);
            }, 30000);
        });
    
        zoomWebSocket.on('message', (data) => {
            const messageStr = data.toString('utf8');
            console.log("[Zoom WebSocket] Decoded message:", messageStr);
    
            let parsedData;
            try {
                parsedData = JSON.parse(messageStr);
            } catch (error) {
                console.error("[Zoom WebSocket] Error parsing WebSocket message:", error);
                return;
            }
    
            const endpointId = subscriptionEndpointMap.get(subscriptionID);
    
            console.log("[Zoom WebSocket] Emitting data to endpoint:", endpointId);
            console.log("[Zoom WebSocket] Received event:", parsedData.event || "Unknown Event", "with data:", parsedData);
            io.to(endpointId).emit('webhookData', { ...parsedData, source: 'websocket' });
        });
    
        zoomWebSocket.on('close', () => {
            console.log("[Zoom WebSocket] WebSocket connection closed");
        });
    }
}