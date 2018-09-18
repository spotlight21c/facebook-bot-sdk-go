# facebook-bot-sdk-go
facebook message bot sdk by golang


# How to use
```golang
import "github.com/spotlight21c/facebook-bot-sdk-go/facebookbot"

bot := facebookbot.New(facebookAppSecret, facebookPageAccessToken)

event, err := bot.ParseRequest(r)
if err != nil {
	fmt.Println(err)
	return
}

for _, entry := range event.Entries {
}

replyMessage := "reply"
if err := bot.PushMessage(senderID, replyMessage); err != nil {
	fmt.Println(err)
}
```
