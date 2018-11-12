function (user, context, callback) {
    function isCommercialUser() {
        return ["BROKER", "FLEET_MANAGER"].indexOf(user.app_metadata.user_type) > -1;
    }

    if(context.clientName === "BrokerPortal") {
        if (!isCommercialUser()) {
            return callback(
                new UnauthorizedError('Not a commercial user: ' + JSON.stringify(user))
            );
        }

    }

    callback(null, user, context);
}
