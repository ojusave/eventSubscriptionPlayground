const { crypto, axios, jwt, baseURL } = require('../config/config');
const io = require('../services/socketio');
const { Cache } = require('../services/cache');
const cache = new Cache();
const webhookConfigurations = {};
const oauthConfigurations = {};
const storedTokens = [];

function noAuth(req, res){
    console.log('Webhook received from Zoom:', req.body);
    console.log('Headers:', req.headers);
    const endpointId = req.params.id;
    io.to(endpointId).emit('webhookData', sendData(req));
    return res.status(200).send('Webhook received');
}

function defaultHeaders(req, res) {
    const endpointId = req.params.id;
    const endpointURL = `${baseURL}/webhook-endpoint/${endpointId}`;
    //const endpointData = webhookConfigurations[endpointId];
    const endpointData = cache.get('webhookConfigurations', endpointId);
    console.log(`defaultHeaders:: endpointData = ${JSON.stringify(endpointData)}`)
    // Removed Redis operations and used in-memory configurations
    if (endpointData === undefined || endpointData === null) {
        console.error("No data found for endpoint:", endpointId);
        return res.status(404).send("Data not found");
    }

    const message = `v0:${req.headers['x-zm-request-timestamp']}:${JSON.stringify(req.body)}`;
    const hashForVerify = crypto.createHmac('sha256', endpointData.config.secretToken).update(message).digest('hex');
    const signature = `v0=${hashForVerify}`;

    if (req.headers['x-zm-signature'] === signature) {
        console.log('Webhook received from Zoom:', req.body);
        console.log('Headers:', req.headers);
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
    const storedEndpointData = cache.get('webhookConfigurations', endpointId);

    if (storedEndpointData === undefined || storedEndpointData === null) {
        console.error("No data found for endpoint:", endpointId);
        return res.status(404).send("Data not found");
    }

    const authConfig = storedEndpointData.config;
    const auth = Buffer.from(`${authConfig.username}:${authConfig.password}`).toString('base64');

    if (req.headers.authorization === `Basic ${auth}`) {
        console.log('Webhook received from Zoom with basic auth:', req.body);
        console.log('Headers:', req.headers);

        // Using the io object to emit to specific sockets
        io.to(endpointId).emit('webhookData', sendData(req));
        return res.status(200).send('Webhook received');
    } else {
        console.log('Basic auth mismatch', req.headers);
        return res.status(403).send('Authorization mismatch');
    }
}


function customHeaderAuth(req, res) {
    const endpointId = req.params.id;
    const endpointURL = `${baseURL}/webhook-endpoint/${endpointId}`;
    const storedEndpointData = cache.get('webhookConfigurations', endpointId);

    if (storedEndpointData === undefined || storedEndpointData === null) {
        console.error("No data found for endpoint:", endpointId);
        return res.status(404).send("Data not found");
    }

    const authConfig = storedEndpointData.config;

    if (req.headers[authConfig.customHeader.toLowerCase()] === authConfig.customValue) {
        console.log('Webhook received with custom header:', req.headers, req.body);
        io.to(endpointId).emit('webhookData', sendData(req));
        return res.status(200).send('Webhook received');
    } else {
        console.log('Headers:', req.headers);
        return res.status(403).send('Header mismatch');
    }
}

function webhookOAuth(req, res) {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const [clientId, clientSecret] = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
        const storedClientSecret = oauthConfigurations[clientId];

        if (storedClientSecret && clientSecret === storedClientSecret) {
            const access_token = jwt.sign({ clientId }, clientSecret, { expiresIn: '1h' });
            storedTokens.unshift(access_token);
            if (storedTokens.length > 10) storedTokens.pop();  // Ensure only the latest 10 tokens are stored

            const responseJson = {
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": "3599"
            };
            console.log(access_token);
            return res.status(200).json(responseJson);
        } else {
            return res.status(401).send('Unauthorized');
        }
    } else {
        return res.status(401).send('Unauthorized');
    }
}


    function tokenAuth(req, res) {
        const authHeader = req.headers.authorization;
        const providedToken = authHeader.split(' ')[1];
    
        if (storedTokens.includes(providedToken)) {
            console.log('Webhook received from Zoom:', req.body);
            const endpointId = req.params.id;
            io.to(endpointId).emit('webhookData', sendData(req));
            return res.status(200).send('Webhook received');
        } else {
            console.error("403 Unauthorized Access Attempt:");
            return res.status(403).send('Signature mismatch');
        }
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
    noAuth,
    defaultHeaders,
    basicAuth,
    customHeaderAuth,
    webhookOAuth,
    tokenAuth,
    sendData
};
