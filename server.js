const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const jwt = require('jsonwebtoken');
const socketIo = require('socket.io');

const http = require('http');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const PORT = 3000;
const baseURL = "https://ojus.ngrok.dev";
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
      origin: "*", 
      methods: ["GET", "POST"]
    }
  });
  const WebSocket = require('ws');


const clientEndpointMap = new Map();
const zoomWebSocketMap = new Map(); 
const subscriptionEndpointMap = new Map();

// Middleware
app.use(express.static(path.join(__dirname, '.')));
app.use(bodyParser.json());
app.use(cors());

let config = {};
let currentAccess_token;
let endpointURL = "";
let activeEndpoints = new Set();

const redis = require('ioredis');
const { access } = require('fs');
const client = redis.createClient({
    host: '127.0.0.1',
    port: 6379
});

client.on('connect', function() {
    console.log('Connected to Redis');
});

client.on('error', function(err) {
    console.log('Redis error: ' + err);
});


io.on('connection', (socket) => {
    console.log('Client connected');
   
    // Extract endpointId from the socket's handshake query
    const endpointId = socket.handshake.query.endpointId;
    if (endpointId) {
        socket.join(endpointId);
        console.log(`Socket joined room: ${endpointId}`);
    }

    socket.on('disconnect', () => {
        console.log('Client disconnected');
        if (endpointId) {
            console.log(`Endpoint ${endpointId} disconnected`);
        }
    });
});


app.post('/configure-webhook', (req, res) => {
    //const { type, clientId, clientSecret, accountId, subscriptionId } = req.body;
    const newEndpoint = `${baseURL}/webhook-endpoint/${crypto.randomBytes(10).toString('hex')}`;
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
    res.sendFile(path.join(__dirname, 'events.html'));
});

app.post('/webhook-endpoint/:id', handleWebhook);

server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});


function handleWebhook(req, res) {
    const endpointId = req.params.id;
    const endpointURL = `${baseURL}/webhook-endpoint/${endpointId}`;

    client.get(endpointURL, (err, result) => {
        if (err) {
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

            if (req.body.event === 'endpoint.url_validation') {
                const hashForValidate = crypto.createHmac('sha256', endpointData.config.secretToken)
                    .update(req.body.payload.plainToken)
                    .digest('hex');
                console.log('Webhook received from Zoom:', req.body);
                console.log('Headers:', req.headers);
                io.to(endpointId).emit('webhookData', sendData(req));

                return res.status(200).json({
                    plainToken: req.body.payload.plainToken,
                    encryptedToken: hashForValidate
                });
            }

            else if (!result) {
                console.error("No data found in Redis for endpoint:", endpointURL);
                return res.status(404).send("Data not found");
            }

            // Note: The "config.type" should be fetched from "endpointData.config.type"
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



function defaultHeaders(req, res, endpointData) {
    const message = `v0:${req.headers['x-zm-request-timestamp']}:${JSON.stringify(req.body)}`;
    const hashForVerify = crypto.createHmac('sha256', endpointData.config.secretToken).update(message).digest('hex');
    const signature = `v0=${hashForVerify}`;
    if (req.headers['x-zm-signature'] === signature) {
        console.log('Webhook received from Zoom:', req.body);
        console.log('Headers:', req.headers);
        const endpointId = req.params.id; // Extract the endpointId from the URL
        io.to(endpointId).emit('webhookData', sendData(req));
        return res.status(200).send('Webhook received');
    } else {
        console.log('Webhook signature mismatch');
        return res.status(403).send('Signature mismatch');
    }
}

function basicAuth(req, res) {
    const endpointId = req.params.id;
    const endpointURL = `${baseURL}/webhook-endpoint/${endpointId}`;

    client.get(endpointURL, (err, result) => {
        if (err) {
            console.error('Error fetching from Redis:', err);
            return res.status(500).send('Internal Server Error');
        }

        if (!result) {
            console.error("No data found in Redis for endpoint:", endpointURL);
            return res.status(404).send("Data not found");
        }

        const endpointData = JSON.parse(result);
        const authConfig = endpointData.config;

        const auth = Buffer.from(`${authConfig.username}:${authConfig.password}`).toString('base64');

        if (req.headers.authorization === `Basic ${auth}`) {
            console.log('Webhook received from Zoom with basic auth:', req.body);
            console.log('Headers:', req.headers);
            
            // Using the io object to emit to specific sockets
            const endpointId = req.params.id; 
            io.to(endpointId).emit('webhookData', sendData(req));

            return res.status(200).send('Webhook received');
        } else {
            console.log('Basic auth mismatch', req.headers);
            return res.status(403).send('Authorization mismatch');
        }
    });
}

function customHeaderAuth(req, res) {
    const endpointId = req.params.id;
    const endpointURL = `${baseURL}/webhook-endpoint/${endpointId}`;

    client.get(endpointURL, (err, result) => {
        if (err) {
            console.error('Error fetching from Redis:', err);
            return res.status(500).send('Internal Server Error');
        }

        if (!result) {
            console.error("No data found in Redis for endpoint:", endpointURL);
            return res.status(404).send("Data not found");
        }

        const endpointData = JSON.parse(result);
        const authConfig = endpointData.config;

        if (req.headers[authConfig.customHeader.toLowerCase()] === authConfig.customValue) {
            console.log('Webhook received with custom header:', req.headers, req.body);

            // Using the io object to emit to specific sockets
            const endpointId = req.params.id; 
            io.to(endpointId).emit('webhookData', sendData(req));

            return res.status(200).send('Webhook received');
        } else {
            console.log('Headers:', req.headers)
            return res.status(403).send('Header mismatch');
        }
    });
}

function webhookOAuth(req, res) {
    const oauthEndpoint = `${baseURL}/webhook-endpoint/oauth`;

    const authHeader = req.headers.authorization;
    if (authHeader) {
        const [clientId, clientSecret] = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
        
        client.hget(oauthEndpoint, clientId, (err, storedClientSecret) => {
            if (err) {
                console.error('Error fetching OAuth config from Redis:', err);
                return res.status(500).send('Internal Server Error');
            }

            if (storedClientSecret && clientSecret === storedClientSecret) {
                const access_token = jwt.sign({ clientId }, clientSecret, { expiresIn: '1h' });
                const newTokenKey = `${oauthEndpoint}:tokens`;
                
client.lpush(newTokenKey, access_token, (err) => {
    if (err) {
        console.error('Error storing access token in Redis:', err);
        return res.status(500).send('Internal Server Error');
    } else {
        // Optionally, limit the list length to a specific number to prevent it from growing indefinitely
        client.ltrim(newTokenKey, 0, 9);  // This keeps the latest 10 tokens

        const responseJson = {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": "3599"
        };
        return res.status(200).json(responseJson);
       
                    }
                    
                });
                console.log(access_token);
            } else {
                return res.status(401).send('Unauthorized');
            }
        });
    } else {
        return res.status(401).send('Unauthorized');
    }
}



function tokenAuth(req, res) {
    const authHeader = req.headers.authorization;
    const providedToken = authHeader.split(' ')[1];  // Extract token from "Bearer <token>"

    const tokenKey = `${baseURL}/webhook-endpoint/oauth:tokens`;  // Fixed key for storing tokens

    // Check if the provided token exists in the Redis list
    client.lrange(tokenKey, 0, -1, (err, storedTokens) => {
        if (err) {
            console.error('Error fetching access tokens from Redis:', err);
            return res.status(500).send('Internal Server Error');
        }

        if (storedTokens.includes(providedToken)) {
            console.log('Webhook received from Zoom:', req.body);
            const endpointId = req.params.id;
            io.to(endpointId).emit('webhookData', sendData(req));
            return res.status(200).send('Webhook received');
        } else {
            console.error("403 Unauthorized Access Attempt:");
            console.error("Endpoint:", `${baseURL}/webhook-endpoint/${req.params.id}`);
            console.error("Request Body:", req.body);
            console.error("Request Headers:", req.headers);
            console.error("Tokens", storedTokens, providedToken);
            return res.status(403).send('Signature mismatch');
        }
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






function broadcastToWebsocketClients(data) {
    wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(data));
        }
    });
}

function sendData(req) {
    const url1 = baseURL + req.url;

    if (activeEndpoints.has(url1)) {
        return {
            method: req.method,
            url: url1,
            host: req.headers.host,
            date: new Date().toISOString(),
            size: req.headers['content-length'] + " bytes",
            headers: req.headers,
            body: req.body,
            event_name: req.body.event
        };
    } else {
        console.log("URL mismatch", url1);
    }
}

