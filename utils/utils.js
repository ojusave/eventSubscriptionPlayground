const { crypto, axios, jwt, baseURL } = require('../config/config');
const { client } = require('../services/redis');
const io = require('../services/socketio');

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



function sendData(req) {
    const url1 = baseURL + req.url;


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
    
}

module.exports = {
    defaultHeaders,
    basicAuth,
    customHeaderAuth,
    webhookOAuth,
    tokenAuth,
    sendData
};
