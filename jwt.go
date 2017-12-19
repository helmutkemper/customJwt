package customJwt

import (
  "github.com/helmutkemper/jwt-go"
  log "github.com/helmutkemper/seelog"
  "errors"
  "io/ioutil"
  "net/http"
  "github.com/helmutkemper/gOsmServer/gosmSession"
  "github.com/helmutkemper/gOsmServer/setupProject"
  "github.com/helmutkemper/gOsmServer/gosmUser"
)

type CustomClaims struct {
  UserName            string              `json:"userName"`
  Levels              []int               `json:"levels"`
  jwt.StandardClaims
}

var jwtExpire float64

func SessionTest( r *http.Request ) ( jwt.Claims, error ) {
  var err error
  var key []byte

  key, err = ioutil.ReadFile( setupProject.Config.Rsa.PublicPen )
  if err != nil {
    log.Critical( "unable to load rsa private key" )
    return nil, errors.New( "unable to load rsa private key" )
  }

  session := gosmSession.GetSession(r)

  // Parse takes the token string and a function for looking up the key. The latter is especially
  // useful if you use multiple keys for your application.  The standard is to use 'kid' in the
  // head of the token to identify which key to use, but the parsed token (head and claims) is provided
  // to the callback, providing flexibility.
  token, err := jwt.Parse(session.Values["jwt"].(string), func(token *jwt.Token) (interface{}, error) {
    // Don't forget to validate the alg is what you expect:
    if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
      log.Info( "security token error" )
      return errors.New( "security token error" ), nil
    }

    // hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
    return jwt.ParseRSAPublicKeyFromPEM( key )
  })

  if token.Valid == false {
    log.Info( "security token error" )
    return nil, errors.New( "security token error" )
  }

  if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
    return claims, nil
  } else {
    log.Info( "security token error" )
    return nil, errors.New( "security token error" )
  }
}

func SessionMake( user gosmUser.User, w http.ResponseWriter, r *http.Request ) error {
  key, err := ioutil.ReadFile( setupProject.Config.Rsa.PrivatePen )
  if err != nil {
    return errors.New( "unable to load rsa private key" )
  }

  parseKey, err := jwt.ParseRSAPrivateKeyFromPEM( key )
  if err != nil {
    return errors.New( "private key error" )
  }
jwtExpire = 1893456000
  var claims CustomClaims = CustomClaims{
    UserName: user.UserName,
    Levels: user.Levels,
    StandardClaims: jwt.StandardClaims{
      ExpiresAt: int64( jwtExpire ),
    },
  }

  token, err := jwt.NewWithClaims( jwt.SigningMethodRS256, claims ).SignedString( parseKey )

  session := gosmSession.GetSession(r)
  session.Values["jwt"]  = token
  session.Save(r, w)

  return err
}
