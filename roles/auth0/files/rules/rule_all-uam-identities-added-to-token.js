function (user, context, callback) {
    const allianzNamespace = 'https://allianz.co.uk/';

    context.accessToken[allianzNamespace + "ids/uamc"] = user.email;

    callback(null, user, context);
}
