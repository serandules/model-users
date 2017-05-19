var bcrypt = require('bcrypt');
var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var permission = require('permission');
var types = require('validators').types;

var SALT_WORK_FACTOR = 10;

var user = Schema({
    has: {type: Object, default: {}},
    allowed: {type: Object, default: {}},
    password: {type: String},
    email: {
        type: String,
        index: {unique: true},
        required: true,
        validator: types.email()
    },
    tokens: {
        type: [Schema.Types.ObjectId],
        ref: 'tokens',
        validator: types.ref()
    },
    roles: {
        type: [Schema.Types.ObjectId],
        ref: 'roles',
        validator: types.ref()
    },
    alias: {
        type: String,
        validator: types.name({
            length: 100
        })
    },
    firstname: {
        type: String,
        validator: types.name({
            length: 100
        })
    },
    lastname: {
        type: String,
        validator: types.name({
            length: 100
        })
    },
    birthday: {
        type: Date,
        validator: types.birthday()
    },
    locations: {
        type: [Schema.Types.ObjectId],
        ref: 'locations',
        validator: types.ref()
    },
    phones: {
        type: Schema.Types.Mixed,
        validator: types.phones({
            max: 5
        })
    },
    socials: {
        type: Schema.Types.Mixed,
        validator: types.socials({
            max: 20
        })
    }
}, {collection: 'users'});

user.set('toJSON', {
    getters: true,
    //virtuals: false,
    transform: function (doc, ret, options) {
        delete ret.password;
        delete ret._id;
        delete ret.__v;
    }
});

user.methods.auth = function (password, callback) {
    bcrypt.compare(password, this.password, function (err, res) {
        callback(err, res);
    });
};

user.methods.can = function (perm, action) {
    return permission.has(this.has, perm.split(':'), action);
};

user.methods.permit = function (perm, actions, done) {
    actions = actions instanceof Array ? actions : [actions];
    permission.add(this.has, perm.split(':'), actions);
    this.save(done);
};

var encrypt = function (password, done) {
    bcrypt.genSalt(SALT_WORK_FACTOR, function (err, salt) {
        if (err) {
            return done(err);
        }
        bcrypt.hash(password, salt, function (err, hash) {
            if (err) {
                return done(err);
            }
            done(false, hash);
        });
    });
};

user.pre('save', function (next) {
    var user = this;
    if (!user.isModified('password')) {
        return next();
    }
    encrypt(user.password, function (err, hash) {
        if (err) {
            return next(err);
        }
        user.password = hash;
        next();
    });
});

user.pre('update', function (next) {
    var user = this;
    if (!user.isModified('password')) {
        return next();
    }
    encrypt(user.password, function (err, hash) {
        if (err) {
            return next(err);
        }
        user.password = hash;
        next();
    });
});

user.virtual('id').get(function () {
    return this._id;
});
/*
 user.statics.find = function (options, callback) {
 if (options.email) {
 this.findOne({
 email: email
 }, callback);
 return;
 }
 callback(null);
 };*/

module.exports = mongoose.model('users', user);