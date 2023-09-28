const {cors, express , path, session} =  require('../config/config');


module.exports = (app) => {
    app.use(cors());
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use(express.static(path.join(__dirname, 'public')));
    app.use(session({
        secret: 'secret',
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false }
    }));
};
