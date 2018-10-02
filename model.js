var bcrypt = require('bcrypt');
var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var mongutils = require('mongutils');
var mongins = require('mongins');
var permission = require('permission');
var validators = require('validators');
var types = validators.types;
var values = validators.values;

var SALT_WORK_FACTOR = 10;

var user = Schema({
  password: {
    type: String,
    required: true,
    encrypted: true,
    validator: types.password({
      block: function (o, done) {
        var data = o.data;
        done(null, {
          email: data.email
        });
      }
    })
  },
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
  // TODO: check how groups: undefined resulted in database, whether empty array or null
  groups: {
    type: [Schema.Types.ObjectId],
    ref: 'groups',
    validator: types.groups(),
    value: values.groups()
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

user.plugin(mongins);
user.plugin(mongins.createdAt());
user.plugin(mongins.updatedAt());

mongutils.ensureIndexes(user, [
  {createdAt: -1, _id: -1}
]);

user.set('toJSON', {
  getters: true,
  //virtuals: false,
  transform: function (doc, ret, options) {
    delete ret.password;
    delete ret._id;
    delete ret.__v;
  }
});

user.methods.auth = function (password, done) {
  if (!password || !this.password) {
    return done(null, false);
  }
  bcrypt.compare(password, this.password, done);
};

user.methods.can = function (perm, action) {
  return permission.has(this.has, perm.split(':'), action);
};

user.methods.permit = function (perm, actions, done) {
  actions = actions instanceof Array ? actions : [actions];
  permission.add(this.has, perm.split(':'), actions);
  this.save(done);
};

module.exports = mongoose.model('users', user);