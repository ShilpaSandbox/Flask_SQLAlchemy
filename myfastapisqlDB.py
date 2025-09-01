#FastAPI with SQL intergration
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional, List
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session   
from passlib.context import CryptContext 
import jwt  
from datetime import datetime, timedelta

SECRET_KEY="codewithjosh"
ALGORITHM="HS256"       
TOKEN_EXPIRES=30



# Database setup
DATABASE_URL = "sqlite:///./EmpUsers.db"    
#SQL can only handle one thread at a time. FASTAPI can handle multiple requests at a time.
#So we need to add connect_args={"check_same_thread": False} to the create_engine function to allow multiple threads to access the database.    
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Create a configured "Session" class for the database or database session.

# To prevent the session from automatically committing changes to the database and to 
# prevent it from automatically flushing changes (PUT) to the database,
#  we set autocommit=False and autoflush=False.

# The bind=engine argument binds the session to the database engine we created earlier. 

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarativebase is a base class for our database models to inherit from.
# It provides a way to define the structure of our database tables using Python classes.
# Each model class that inherits from Base will be mapped to a corresponding table in the database.
# This allows us to interact with the database using Python objects instead of writing raw SQL queries.

Base = declarative_base()


# We will create a model named User that will inherit from Base.
#Database Model is a row in a table. Each row has columns with a unique id.
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable = False)
    email = Column(String(100), unique=True, nullable=False )
    role = Column(String(50), nullable=False)
    hashed_pwd = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)

#This model needs to speak to our Engine. 
Base.metadata.create_all(engine)

# Pydantic Models are like Dataclasses.
# Inherit from BaseModel
class UserCreate(BaseModel):
    name: str
    email: str
    role: str
    password: str   

# To protect sensitive information like passwords or internal fields such as database IDs,
#  we create a separate response model that excludes such fields.   
class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: str
    is_active: bool

class UserLogin(BaseModel):
    email: str
    password: str

#JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained
#  way for securely transmitting information between parties as a JSON object.
#JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key
#  pair using RSA or ECDSA.
#In the context of JSON Web Tokens (JWT), an access token is a security token used 
# for authorization. It grants a client application access to specific resources 
# on behalf of an authenticated user. 
# 
# They consist of 3 parts: Header, Payload, and Signature.  
#The header typically consists of two parts: the type of the token, which is JWT, 
# and the signing algorithm being used, such as HMAC SHA256 or RSA.
# The second part of the token is the payload, which contains the claims. 
# Claims are statements about an entity (typically, the user) and additional data.
#  There are three types of claims: registered, public, and private claims.
# 
# Common claims include the issuer (iss), subject (sub), audience (aud), 
# expiration time (exp), and issued-at time (iat).
#Signature: Used to verify the token's integrity and authenticity. It is created by 
# signing the header and payload with a secret key or a private key,
#  ensuring the token has not been tampered with.

#Flow
# In authentication, when the user successfully logs in using their credentials, 
# a JSON Web Token will be returned.
#A user authenticates with an authorization server (e.g., by providing credentials).
# Upon successful authentication and authorization, 
# the authorization server issues an access token to the client application.
#The client application then includes this access token in subsequent requests 
# to a resource server (API) to access protected data or functionalities.
#The resource server validates the access token (checking its signature,
#  expiration, and claims) before granting access to the requested resource.

#Encoding a JWT involves transforming the header and payload into a compact, URL-safe format. 
# The header, which states the signing algorithm and token type, and the payload, which includes 
# claims like subject, expiration, and issue time, are both converted to JSON then Base64URL encoded. 
# These encoded parts are then concatenated with a dot, after which a signature is generated 
# using the algorithm specified in the header with a secret or private key.
#  This signature is also Base64URL encoded, resulting in the final JWT string that represents 
# the token in a format suitable for transmission or storage.

#Decoding a JWT reverses this process by converting the Base64URL encoded header and payload 
# back into JSON, allowing anyone to read these parts without needing a key. 
# However, "decoding" in this context often extends to include verification of the token's signature. 
# This verification step involves re-signing the decoded header and payload with the same algorithm and key used initially, 
# then comparing this new signature with the one included in the JWT.
#  If they match, it confirms the token's integrity and authenticity, ensuring it hasn't been tampered with since issuance.

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None 


    # Configure Pydantic to work with SQLAlchemy models
    class Config:
        from_attributes = True 

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

#Security and Password Hashing
#Verify and hash the password
def verify_pwd(plain_pwd:str, hashed_pwd:str) ->bool:
    return pwd_context.verify(plain_pwd, hashed_pwd)



#Make the hash
def get_pwd_hash(password:str):
    return pwd_context.hash(password)

#Holds the dictionary of the subject. Holds the access token.
#In the context of JWT, the subject is typically the user or entity that the token represents
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()

    #Set the expiry time to 15mins in case the expires_delta is not provided
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    #Update the dictionary with the expiry time
    to_encode.update({"exp": expire})

    #Encode the dictionary by giving the SECRET key and the algorithm
    #this is the json web token
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt  

def verify_token(token:str) -> TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        #Email is the subject to identify the user
        
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        #To create an instance of the TokenData class with the email extracted from the token payload. 
        # Email is the subject to identify the user.
        # This instance can then be used to access the email attribute elsewhere in the application.
        #TokenData is a Pydantic model that holds the email of the user extracted from the token.
        # It is used to validate the token and to get the email of the user.
        # If the email is not present in the token, an HTTPException is raised.
        # This helps in ensuring that the token is valid and contains the necessary information.
        # If the token is valid, the function returns an instance of TokenData containing the email.

        token_data = TokenData(email=email)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token_data   

# to handle the database session
def get_db():    
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()  

get_db()


#Auth Dependensies
# Depends is imported from fastapi and is used to declare dependencies for path operation functions.
# The line of code depends on having a token and db session to get the current user.



def get_current_user(token: str = Depends(OAuth2PasswordBearer(tokenUrl="token")), db: Session = Depends(get_db)):
    token_data = verify_token(token)

    #Query the database to get the user with the email from the token.
    user = db.query(User).filter(User.email == token_data.email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="User does not exist", 
            headers={"WWW-Authenticate": "Bearer"}
            )
    return user 

#The user logged in is also the current active user.
def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=404, detail="Inactive user")
    return current_user 


app = FastAPI(title="FastAPI with Josh")


#Auth Endpoints
# Register user
# Log the user in and give it an access token.

@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    # Check if the email already exists in the database
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=404, detail="Email already registered")
    
    # Hash the password before storing it in the database
    hashed_password = get_pwd_hash(user.password)
    
    # Create a new user instance
    db_user = User(
        name=user.name,
        email=user.email,
        role=user.role,
        hashed_pwd=hashed_password
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_pwd(form_data.password, user.hashed_pwd):
        raise HTTPException(status_code=404, detail="Incorrect email or password")
    
    if not user.is_active:
        raise HTTPException(status_code=404, detail="Inactive user")
    access_token_expires = timedelta(minutes=TOKEN_EXPIRES)

    #data is a dictionary that holds the subject(sub) which is the email of the user
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}       


#  Endpoint Landing page
@app.get("/")
def read_root():
    return {"message": "Intro to the FastAPI with SQL Integration!"}

#Get profile
@app.get("/profile/", response_model=UserResponse)
def get_profile(current_user: User = Depends(get_current_active_user)):
    return current_user

#Verify token
@app.get("/verify-token/")
def verify_token_endpoint(current_user: User = Depends(get_current_active_user)):
    return {
        "valid": True,
        "user":{"id": current_user.id, "name": current_user.name, "email": current_user.email, "role": current_user.role},  
                
        }



#Endpoint : to retrieve(get) an existing User  (CRUD)
@app.get("/users/{user_id}", response_model=UserResponse)
def get_user(user_id:int, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    # This function get_user() depends on the function get_db() to provide a database session.
    
    #get one user by quering the db that matched the user_id
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

#Endpoint : to create a new User
@app.post("/users/", response_model=UserResponse) 

#Pydantic is a Python library used for data validation and settings management using Python type annotations.
# It defines a data schema for creating a new user.
#UserCreate is the Pydantic model that will be used to validate the incoming request body.
#UserCreate is a class that inherits from BaseModel and defines the fields required to create a new user.
def create_user(user: UserCreate, current_user: User = Depends(get_current_active_user),db: Session = Depends(get_db)):

    #Display the user details received in the request body from class UserCreate
    if user:

        print(f"User details received from class UserCreate: Name: {user.name}, Email: {user.email}, Role: {user.role}")  

    #Display the number of users in the database before adding a new user
    myuser_count = db.query(User).count()
    print(f"Number of users in the database before adding a new user: {myuser_count}")        

    # user belongs to class UserCreate
    # User belongs to class User which is the database model
    
    #So we create a new instance of the User model and pass the values from the UserCreate model to the User model
    #This is called mapping or transforming data from one model to another model
    #We do this because the UserCreate model is not mapped to the database,
    # but the User model is mapped to the database.
    
    #We then add this new instance to the database session and commit the changes to the database.
    #Finally we return the newly created user as a response.

    #The response_model=UserResponse parameter in the route decorator specifies 
    # that the response will be validated and serialized using the UserResponse Pydantic model.
    #This ensures that the response only includes the fields defined in UserResponse, 
    # excluding any sensitive information like passwords or internal fields such as database IDs.
    #This is a good practice to protect sensitive information and to ensure that the response only includes the necessary fields.
    #This is especially important when dealing with user data, as it helps to prevent accidental exposure of sensitive information. 


    # Check if the email in user.email (of UserCreate)(which is the newly to be intered user details)
    #  already exists in class User (which mirrors the db)
    # as email field is unique to any user

    #Create a new user only if the email does not exist in the database
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_pwd_hash(user.password)
    db_user= User(
        name=user.name,
        email=user.email,
        role=user.role,
        hashed_pwd=hashed_password
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)  # Refresh the instance to get the generated ID and other defaults
    return db_user

# The response_model=UserResponse parameter in the route decorator specifies that the response will be validated and serialized using the UserResponse Pydantic model.
# This ensures that the response only includes the fields defined in UserResponse, excluding any sensitive information


@app.delete("/users/{user_id}")
def delete_user(user_id: int, current_user: User = Depends(get_current_active_user),db: Session = Depends(get_db)):
    """Delete a user"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot delete yourself")

    db.delete(user)
    db.commit()
    return {"message": "User deleted"}


@app.put("/users/{user_id}", response_model=UserResponse)
def update_user(user_id: int, update_user: UserCreate,current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Update a user"""
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db_user.name = update_user.name
    db_user.email = update_user.email
    db_user.role = update_user.role


    
    db.commit()
    db.refresh(db_user)
    return db_user

# Define pwd_context for password hashing and verification
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

