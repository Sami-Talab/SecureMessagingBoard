import Joi from 'joi';

const schemas = {
  setUsername: Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
  }),
  createMessage: Joi.object({
    recipientId: Joi.string().required(),
    contentEncrypted: Joi.string().required(),
  }),
};

const validator = (schemaName) => {
  return (req, res, next) => {
    const { error } = schemas[schemaName].validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }
    next();
  };
};

export default validator;

