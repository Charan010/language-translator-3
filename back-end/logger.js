const logger = (req, res, next) => {
    const excludedExtensions = [
      '.css', '.js', '.png', '.jpg', '.jpeg',
      '.ico', '.svg', '.woff', '.ttf', '.map'
    ];
  
    const shouldSkip = excludedExtensions.some(ext =>
      req.originalUrl.toLowerCase().endsWith(ext)
    );

  
    if (!shouldSkip) {
      const ip = req.ip || req.connection.remoteAddress;
      const port = req.socket.remotePort;
      const method = req.method;
      const route = req.originalUrl;
      
      console.log(`[${new Date().toISOString()}] Route: ${route} | Method: ${method} | IP: ${ip} | Port: ${port}`);
    }
  
    next();
  };
  
  module.exports = logger;  