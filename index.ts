import AWS from 'aws-sdk';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcrypt';
import { sign, verify } from 'jsonwebtoken';

const dynamo = new AWS.DynamoDB.DocumentClient();
const tableName = 'http-crud-pintap-user'
const secret = '123456789qwertyuiop'

const handler = async (event, context) => {
  let body:any;
  let requestJSON:any;
  let statusCode:number = 200;
  let hashedPass:any;
  const headers = {
    "Content-Type": "application/json"
  };

  try {
    switch (event.routeKey) {
      case "DELETE /users/{id}":
        requestJSON = JSON.parse(event.body);
        if (requestJSON.token) {
          if (verify(requestJSON.token, secret)) {
            await dynamo
              .delete({
                TableName: tableName,
                Key: {
                  id: event.pathParameters.id
                }
              })
              .promise();
            body = `Deleted item ${event.pathParameters.id}`;
          }
        } else {
          body = `Unauthorized`;
        }
        break;
      case "GET /users/{id}":
        requestJSON = JSON.parse(event.body);
        if (requestJSON.token) {
          if (verify(requestJSON.token, secret)) {
            body = await dynamo
              .get({
                TableName: tableName,
                Key: {
                  id: event.pathParameters.id
                }
              })
              .promise();
          }
        } else {
          body = `Unauthorized`;
        }
        break;
      case "GET /users":
        requestJSON = JSON.parse(event.body);
        if (requestJSON.token) {
          if (verify(requestJSON.token, secret)) {
            body = await dynamo.scan({ TableName: tableName }).promise();
          }
        } else {
          body = `Unauthorized`;
        }
        break;
      case "PUT /users":
        requestJSON = JSON.parse(event.body);
        hashedPass = await bcrypt.hash(requestJSON.password);
        await dynamo
          .put({
            TableName: tableName,
            Item: {
              id: requestJSON.id,
              name: requestJSON.name,
              password: hashedPass,
              createdAt: new Date(),
              updatedAt: new Date(),
              deletedAt: null
            }
          })
          .promise();
        body = `Put user ${requestJSON.id}`;
        break;
      case "POST /users":
        requestJSON = JSON.parse(event.body);
        if (requestJSON.token) {
          if (verify(requestJSON.token, secret)) {
            hashedPass = await bcrypt.hash(requestJSON.password);
            await dynamo
              .update({
                TableName: tableName,
                Item: {
                  id: uuidv4(),
                  name: requestJSON.name,
                  password: hashedPass,
                  createdAt: new Date(),
                  updatedAt: new Date(),
                  deletedAt: null
                }
              })
              .promise();
            body = `Put user ${requestJSON.id}`;
          }
        } else {
          body = `Unauthorized`;
        }
        break;
      case "POST /login":
        requestJSON = JSON.parse(event.body);
        body = await dynamo
          .get({
            TableName: tableName,
            Key: {
              id: event.pathParameters.id
            }
          })
          .promise();
        const checkPassword = await bcrypt.compare(requestJSON.password, body.password);
        if (checkPassword) {
          body.token = sign({id: body.id}, secret);
          body.message = 'login success';
        } else {
          body.token = null;
          body.message = 'login failed'
        }
      
      default:
        throw new Error(`Unsupported route: "${event.routeKey}"`);
    }
  } catch (err) {
    statusCode = 400;
    body = err.message;
  } finally {
    body = JSON.stringify(body);
  }

  return {
    statusCode,
    body,
    headers
  };
};

export { handler };
