const socketIo = require('socket.io');
const { server } = require('../config/config');



const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

    // Socket.io Connection Setup
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


module.exports = io;

