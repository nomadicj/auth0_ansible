function (user, context, callback) {
    function isBackofficeUser() {
        return ["BDM"].indexOf(user.app_metadata.user_type) > -1;
    }

    if(context.clientName === "UAM-C Back-Office") {
        if (!isBackofficeUser()) {
            return callback(
                new UnauthorizedError('Not a back office user: ')
            );
        }
    }

     callback(null, user, context);
}
