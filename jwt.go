package customJwt

import (
  "github.com/helmutkemper/jwt-go"
  log "github.com/helmutkemper/seelog"
  "errors"
  "io/ioutil"
  "github.com/helmutkemper/gOsm/consts"
  "net/http"
  "github.com/helmutkemper/gOsmServer/gosmSession"
)

type CustomClaims struct {
  Name                string              `json:"id"`
  Levels              []int               `json:"admin"`
  jwt.StandardClaims
}

var jwtClaims map[string]interface{}
var jwtExpire float64
var jwtTest bool

func SessionTest( r *http.Request ) ( jwt.Claims, error ) {
  var err error
  var key []byte

  key, err = ioutil.ReadFile( consts.GEO_TEST_RSA_PUBLIC_KEY )
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
    jwtClaims = claims[ "user" ].( map[ string ]interface{} )
    jwtExpire = claims[ "exp" ].( float64 )
    jwtTest   = true

    return claims, nil
  } else {
    log.Info( "security token error" )
    return nil, errors.New( "security token error" )
  }
}

func SessionMake( w http.ResponseWriter, r *http.Request ) error {
  if jwtTest != true {
    return errors.New( "security process error" )
  }

  key, err := ioutil.ReadFile( consts.GEO_RSA_PRIVATE_KEY )
  if err != nil {
    return errors.New( "unable to load rsa private key" )
  }

  parseKey, err := jwt.ParseRSAPrivateKeyFromPEM( key )
  if err != nil {
    return errors.New( "private key error" )
  }

  var claims CustomClaims = CustomClaims{
    Name: jwtClaims[ "name" ].( string ),
    Levels: jwtClaims[ "levels" ].( []int ),
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
