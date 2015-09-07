var bcrypt = require('bcrypt');
var SALT_WORK_FACTOR = 10;

var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var user = Schema({
    email: String,
    password: String,
    token: {type: Schema.Types.ObjectId, ref: 'Token'},
    permissions: {},
    alias: String,
    firstname: String,
    lastname: String,
    birthday: Date,
    addresses: {},
    mobiles: [String],
    socials: {}
});

user.set('toJSON', {
    getters: true,
    //virtuals: false,
    transform: function (doc, ret, options) {
        delete ret.password;
        delete ret._id;
    }
});

user.methods.auth = function (password, callback) {
    bcrypt.compare(password, this.password, function (err, res) {
        callback(err, res);
    });
};

/**
 * *
 * vehicles/users/1/comments
 * vehicles:users:1:comments
 * vehicles:create:*
 * vehicles:read:*
 * vehicles:read:1
 * vehicles:read:1,2
 * {
 *
 * }
 * @param permission
 */
user.methods.can = function (permission) {
    var perms = this.permissions;
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

var update = function (next) {
    var user = this;
    var $setOnInsert = user._update.$setOnInsert;
    if (!$setOnInsert) {
        return next();
    }
    var password = $setOnInsert.password;
    if (!password) {
        return next();
    }
    encrypt(password, function (err, hash) {
        if (err) {
            return next(err);
        }
        $setOnInsert.password = hash;
        next();
    });
};

user.pre('update', update);

user.pre('findOneAndUpdate', update);

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

module.exports = mongoose.model('User', user);