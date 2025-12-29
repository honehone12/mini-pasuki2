package main

import (
	"context"
	"flag"
	"log"
	"mini-pasuki2/binid"
	"mini-pasuki2/ent"
	"os"

	"github.com/go-playground/validator/v10"
	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
)

type Args struct {
	Name  string `validate:"min=1,max=256"`
	Email string `validate:"email,max=256"`
}

func main() {
	name := flag.String("name", "", "user name")
	email := flag.String("email", "", "user email")
	flag.Parse()

	v := validator.New()
	args := Args{
		Name:  *name,
		Email: *email,
	}
	if err := v.Struct(&args); err != nil {
		log.Fatalln(err)
	}

	if err := godotenv.Load("../../.env"); err != nil {
		log.Fatalln(err)
	}

	mysqlUri := os.Getenv("MYSQL_URI")
	if len(mysqlUri) == 0 {
		log.Fatalln("could not found env for mysql uri")
	}

	client, err := ent.Open("mysql", mysqlUri, ent.Debug())
	if err != nil {
		log.Fatalln(err)
	}
	defer client.Close()

	id, err := binid.NewSequential()
	if err != nil {
		log.Fatalln(err)
	}

	ctx := context.Background()
	app, err := client.User.Create().
		SetID(id).
		SetName(args.Name).
		SetEmail(args.Email).
		Save(ctx)
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf(
		"created user id: %s name: %s email: %s\n",
		id.String(),
		app.Name,
		app.Email,
	)
}
