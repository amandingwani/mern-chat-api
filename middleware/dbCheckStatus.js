function dbCheckStatus(req, res, next) {
    if (process.mongooseConnected) {
        next()
    }
    else {
        res.json({
            error: "Db not connected"
        })
    }
}

module.exports = dbCheckStatus;