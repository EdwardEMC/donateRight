module.exports = function(sequelize, DataTypes) {
    var EventHistory = sequelize.define("EventHistory", {
        title: {
            type: DataTypes.STRING,
            allowNull: false
        },
        description: {
            type: DataTypes.STRING,
            allowNull: false
        },
        charityKey: {
            type: DataTypes.STRING,
            allowNull: false
        }
    },
    {
        freezeTableName: true
    });

    EventHistory.associate = function(models) {
        EventHistory.belongsTo(models.Charity, {
          foreignKey: {
            allowNull: false
          },
          onDelete: "cascade"
        });
    };

    return EventHistory;
}; 