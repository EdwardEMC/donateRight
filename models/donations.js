var bcrypt = require("bcryptjs");

module.exports = function(sequelize, DataTypes) {
    var Donations = sequelize.define("Donations", {
        email: {
            type: DataTypes.STRING,
            allowNull: false,
            unique: true,
            validate: {
                isEmail: true
            }
        },
        password: {
            type: DataTypes.STRING,
            allowNull: false
        }
    });

    Donations.prototype.validPassword = function(password) {
        return bcrypt.compareSync(password, this.password);
    };

    Donations.addHook("beforeCreate", function(donations) {
        donations.password = bcrypt.hashSync(donations.password, bcrypt.genSaltSync(10), null);
    });
    return Donations;
};