from fastapi import FastAPI,status,Depends,HTTPException
from pydantic import BaseModel
from typing import List
from fastapi_jwt_auth import AuthJWT

app=FastAPI()

class Settings(BaseModel):
    authjwt_secret_key:str='303c082173f36d4c4f85a31ec592103c7c99160a12fd858359fdf51b830344e4'
    

@AuthJWT.load_config
def get_config():
    return Settings()

class User(BaseModel):
    username:str
    email:str
    password:str
    
    # optional 
    class Config:
        schema_extra={
            "example":{
                "username":"ganesh kunwar",
                "email":"gkunwar07@gmail.com",
                "password":"password"
            }
        }
        
        
class UserLogin(BaseModel):
    username:str
    password:str
    
    class Config:
        schema_extra={
            "example":{
                "username":"ganesh",
                "password":"password"
            }
        }
        
users=[]    

@app.get("/")
async def index():
    return{"message":"Hello world !"}

# create user

@app.post('/signup',status_code=status.HTTP_201_CREATED)
async def create_user(user:User):
    new_user=User(
        username=user.username,
        email=user.email,
        password=user.password 
    )
    users.append(new_user)
    
    return new_user






# getting all users
@app.get('/users',response_model=List[User])
def get_users():
    return users

@app.post('/login')
async def login(user:UserLogin,Authorize:AuthJWT=Depends()):
    for u in users:
        # if (u["username"]==user.username) and (u["password"]==user.password): #for dictonaries
        if u.username==user.username and u.password==user.password:
            # access token
            access_token=Authorize.create_access_token(subject=user.username)
            # refresh token
            refresh_token=Authorize.create_refresh_token(subject=user.username)
            
            return {"access_token":access_token,"refresh_token":refresh_token}
        
        
        raise HTTPException(status_code='401',detail="Invalid username or password")
            
    
@app.get('/protected')
def get_logged_in_user(Authorize:AuthJWT=Depends()):
    try:
        Authorize.jwt_required()
        
    except Exception as e:
        raise HTTPException (status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")
    
    current_user=Authorize.get_jwt_subject()
    
    return{"current_user":current_user}


@app.get('/new_token')
async def create_new_token(Authorize:AuthJWT=Depends()):
    try:
        Authorize.jwt_refresh_token_required()
        
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid Token")
    
    access_token=Authorize.create_access_token(subject='current_user')
    
    return{"new_access_token":access_token}

@app.post('/fresh_login')
async def fresh_login(user:User,Authorize:AuthJWT=Depends()):
    for u in users:
        if u.username==user.username and u.password==user.password:
            fresh_token=Authorize.create_access_token(subject=user.username,fresh=True)
            
            return {"fresh_token":fresh_token}
        
        
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid username or password")
    
    
    @app.get('/fresh_url')
    async def get_user(Authorize:AuthJWT=Depends()):
        try:
            Authorize.fresh_jwt_required()
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")
        
        current_user=Authorize.get_jwt_subject()

        
        return{"current_user":current_user}