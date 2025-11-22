// module.exports = (fn) => {
//   return (req, res, next) => {
//     Promise.resolve(fn(req, res, next)).catch((err) => {
//       console.error(`[${req.method}] ${req.originalUrl}`);
//       console.error(err.stack);
//       next(err);
//     });
//   };
// };

module.exports = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)) // resolves successfully
    .catch(next); // rejects with an error, so we pass it to next()
};
