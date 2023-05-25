package database

import (
	"context"
	"log"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type AccountVariables struct {
	Name, Email, Password, About string
}

var Account AccountVariables
var Connect = Connection()

func Connection() *mongo.Client {
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")

	client, err := mongo.Connect(context.TODO(), clientOptions)

	if err != nil {
		log.Fatal(err)
	}

	return client
}

func InsertData(inputData interface{}) {
	collection := Connect.Database("goLang").Collection("data")

	if _, err := collection.InsertOne(context.TODO(), inputData); err != nil {
		log.Fatal(err)
	}
}

func FindAccount(myEmail, myPassword string) bool {
	collection := Connect.Database("goLang").Collection("data")
	collection.FindOne(context.TODO(), bson.M{"email": myEmail}).Decode(&Account)

	err := bcrypt.CompareHashAndPassword([]byte(Account.Password), []byte(myPassword))

	return err == nil
}

func Updatedata(key, value string) bool {
	collection := Connect.Database("goLang").Collection("data")
	filter := bson.M{"email": Account.Email, "password": Account.Password}
	update := bson.M{
		"$set": bson.M{
			key: value,
		},
	}
	_, err := collection.UpdateOne(context.TODO(), filter, update)
	return err == nil
}
