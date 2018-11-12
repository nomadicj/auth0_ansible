function (user, context, callback) {
  var namespace = 'http://allianz-uk.eu/claims/';

  // Add the namespaced tokens. Remove any which is not necessary for your scenario
  context.idToken[namespace + "permissions"] = user.app_metadata.authorization.permissions;
  context.idToken[namespace + "groups"] = user.app_metadata.authorization.groups;
  context.idToken[namespace + "roles"] = user.app_metadata.authorization.roles;

  callback(null, user, context);
}
