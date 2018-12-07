var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var mongins = require('mongins');
var utils = require('utils');
var permission = require('permission');
var validators = require('validators');
var model = require('model');

var types = validators.types;
var values = validators.values;

var user = Schema({
  password: {
    type: String,
    required: true,
    encrypted: true,
    validator: types.password({
      block: function (o, done) {
        done(null, {
          email: o.data.email || o.user.email
        });
      }
    })
  },
  email: {
    type: String,
    index: {unique: true},
    required: true,
    validator: types.email(),
    searchable: true
  },
  tokens: {
    type: [Schema.Types.ObjectId],
    ref: 'tokens',
    validator: types.ref()
  },
  avatar: {
    type: Schema.Types.ObjectId,
    ref: 'binaries',
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
  location: {
    type: Schema.Types.ObjectId,
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

user.plugin(mongins());
user.plugin(mongins.createdAt());
user.plugin(mongins.updatedAt());

model.ensureIndexes(user, [
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
  utils.compare(password, this.password, done);
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