module.exports = function(sequelize, DataTypes) {
    var Charity = sequelize.define("Charity", {
        name: {
            type: DataTypes.STRING,
            allowNull: false
        },
        phoneNumber: {
            type: DataTypes.INTEGER,
            allowNull: false
        },
        email: {
            type: DataTypes.STRING,
            allowNull: false,
            unique: true,
            validate: {
                isEmail: true
            }
        },
        description: {
            type: DataTypes.STRING,
            allowNull: false
        },
        lat: {
            type: DataTypes.DECIMAL(9,6),
            allowNull: true
        },
        lng: {
            type: DataTypes.DECIMAL(9,6),
            allowNull: true
        },
        charityKey: {
            type: DataTypes.STRING,
            allowNull: true
        }
    });
    
    return Charity;
};