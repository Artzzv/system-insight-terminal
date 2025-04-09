
const { PCA } = require('ml-pca');
const { KMeans } = require('ml-kmeans');
const { DecisionTreeClassifier } = require('ml-cart');
const { Matrix } = require('ml-matrix');

/**
 * LogAnalyzer class using unsupervised machine learning techniques
 * to analyze system logs and detect anomalies
 */
class LogAnalyzer {
  constructor() {
    this.initialized = false;
    this.model = null;
    this.featureExtractor = null;
    this.clusters = null;
    this.pca = null;
    this.baselineData = null;
    this.trainingInProgress = false;
  }

  /**
   * Initialize the log analyzer with unsupervised learning models
   */
  async initialize() {
    console.log('Initializing Log Analyzer with unsupervised learning');
    
    // Create feature extractor
    this.featureExtractor = new LogFeatureExtractor();
    
    // Initialize baseline anomaly detection
    this.baselineData = {
      meanVector: null,
      covarianceMatrix: null,
      threshold: 3.0 // Mahalanobis distance threshold for anomaly detection
    };
    
    this.initialized = true;
    
    // Start background training process
    this.startBackgroundTraining();
    
    console.log('Log Analyzer initialization complete');
    return true;
  }
  
  /**
   * Start background training process using system logs
   */
  async startBackgroundTraining() {
    if (this.trainingInProgress) return;
    
    this.trainingInProgress = true;
    console.log('Starting background training for log analysis model');
    
    try {
      // Get training data from system logs (last 2000 events)
      const { exec } = require('child_process');
      const { promisify } = require('util');
      const execPromise = promisify(exec);
      
      // Get system, application, and security logs
      const logTypes = ['System', 'Application', 'Security'];
      let allLogs = [];
      
      for (const logType of logTypes) {
        try {
          const { stdout } = await execPromise(
            `powershell -Command "Get-WinEvent -LogName ${logType} -MaxEvents 500 | Select-Object TimeCreated,Id,LevelDisplayName,Message,ProviderName | ConvertTo-Json"`
          );
          
          const logs = JSON.parse(stdout);
          allLogs = [...allLogs, ...logs];
        } catch (error) {
          console.error(`Error getting ${logType} logs for training:`, error);
        }
      }
      
      if (allLogs.length === 0) {
        console.log('No logs available for training. Using simulated data for model initialization.');
        allLogs = this.generateSimulatedTrainingData();
      }
      
      // Extract features from logs
      const features = this.featureExtractor.extractFeaturesFromLogs(allLogs);
      
      // Train unsupervised models
      await this.trainModels(features);
      
      console.log(`Background training complete. Processed ${allLogs.length} log entries.`);
    } catch (error) {
      console.error('Error in background training:', error);
    } finally {
      this.trainingInProgress = false;
    }
  }
  
  /**
   * Train the unsupervised learning models
   * @param {Array} features - Feature vectors extracted from logs
   */
  async trainModels(features) {
    if (features.length === 0) {
      console.log('No features available for training');
      return;
    }
    
    // Convert features to matrix
    const dataMatrix = new Matrix(features);
    
    // 1. Apply PCA for dimensionality reduction
    this.pca = new PCA(dataMatrix, {
      scale: true
    });
    
    const reducedData = this.pca.predict(dataMatrix, {
      nComponents: Math.min(5, features[0].length) // Reduce to 5 components or fewer
    });
    
    // 2. Apply K-means clustering
    const k = Math.min(5, Math.ceil(Math.sqrt(features.length / 2))); // Rule of thumb for k
    this.clusters = new KMeans(reducedData, k);
    
    // 3. Calculate baseline statistics for anomaly detection
    const means = [];
    for (let i = 0; i < dataMatrix.columns; i++) {
      means.push(dataMatrix.columnMean(i));
    }
    
    this.baselineData.meanVector = means;
    this.baselineData.covarianceMatrix = dataMatrix.transposeView().mmul(dataMatrix).div(dataMatrix.rows);
    
    console.log(`Trained models with ${features.length} samples. Found ${k} clusters.`);
  }
  
  /**
   * Generate simulated training data for model initialization when no real logs are available
   * @returns {Array} Array of simulated log entries
   */
  generateSimulatedTrainingData() {
    console.log('Generating simulated training data for model initialization');
    const simulatedLogs = [];
    
    // Generate 100 simulated log entries
    for (let i = 0; i < 100; i++) {
      simulatedLogs.push({
        TimeCreated: new Date().toISOString(),
        Id: Math.floor(Math.random() * 10000),
        LevelDisplayName: ['Information', 'Warning', 'Error'][Math.floor(Math.random() * 3)],
        Message: `Simulated log message ${i} for model initialization`,
        ProviderName: ['System', 'Security', 'Application'][Math.floor(Math.random() * 3)]
      });
    }
    
    return simulatedLogs;
  }
  
  /**
   * Analyze logs using the trained unsupervised learning models
   * @param {Array} logs - Log entries to analyze
   * @returns {Object} Analysis results
   */
  async analyzeLogs(logs) {
    if (!this.initialized) {
      await this.initialize();
    }
    
    // Extract features from the logs
    const features = this.featureExtractor.extractFeaturesFromLogs(logs);
    
    if (features.length === 0) {
      return {
        summary: {
          total_logs: 0,
          error_count: 0,
          warning_count: 0,
          anomaly_count: 0
        },
        anomalies: [],
        clusters: [],
        time_series: []
      };
    }
    
    // Apply trained models for analysis
    let anomalies = [];
    let clusters = [];
    
    // If models are trained, use them
    if (this.pca && this.clusters && this.baselineData.meanVector) {
      // Apply PCA and clustering to new data
      const dataMatrix = new Matrix(features);
      const reducedData = this.pca.predict(dataMatrix);
      
      // Detect anomalies using Mahalanobis distance
      anomalies = this.detectAnomalies(dataMatrix);
      
      // Assign logs to clusters
      const clusterAssignments = this.clusters.predict(reducedData);
      
      // Organize logs by cluster
      const clusterMap = new Map();
      for (let i = 0; i < clusterAssignments.length; i++) {
        const cluster = clusterAssignments[i];
        if (!clusterMap.has(cluster)) {
          clusterMap.set(cluster, []);
        }
        clusterMap.get(cluster).push(logs[i]);
      }
      
      // Extract cluster information
      clusters = Array.from(clusterMap.entries()).map(([clusterId, clusterLogs]) => {
        const levelCounts = clusterLogs.reduce((acc, log) => {
          const level = log.LevelDisplayName || 'Unknown';
          acc[level] = (acc[level] || 0) + 1;
          return acc;
        }, {});
        
        // Find most common words in this cluster
        const words = this.extractCommonTerms(clusterLogs.map(log => log.Message));
        
        return {
          id: clusterId,
          size: clusterLogs.length,
          common_terms: words.slice(0, 5),
          composition: levelCounts,
          examples: clusterLogs.slice(0, 3).map(log => log.Message)
        };
      });
    }
    
    // Count log levels
    const levelCounts = logs.reduce((acc, log) => {
      const level = log.LevelDisplayName || 'Unknown';
      if (level.includes('Error')) acc.error_count++;
      else if (level.includes('Warning')) acc.warning_count++;
      return acc;
    }, { error_count: 0, warning_count: 0 });
    
    // Generate time series data
    const timeSeriesMap = new Map();
    logs.forEach(log => {
      const timestamp = new Date(log.TimeCreated);
      if (!isNaN(timestamp.getTime())) {
        const hour = timestamp.getHours().toString().padStart(2, '0');
        const timeKey = `${hour}:00`;
        
        if (!timeSeriesMap.has(timeKey)) {
          timeSeriesMap.set(timeKey, { total: 0, error: 0, warning: 0 });
        }
        
        const entry = timeSeriesMap.get(timeKey);
        entry.total++;
        
        const level = log.LevelDisplayName || '';
        if (level.includes('Error')) entry.error++;
        else if (level.includes('Warning')) entry.warning++;
      }
    });
    
    // Convert time series map to array and sort by time
    const timeSeries = Array.from(timeSeriesMap.entries())
      .map(([time, counts]) => ({ time, ...counts }))
      .sort((a, b) => a.time.localeCompare(b.time));
    
    // Group logs by service (provider)
    const serviceDistribution = new Map();
    logs.forEach(log => {
      const provider = log.ProviderName || 'Unknown';
      if (!serviceDistribution.has(provider)) {
        serviceDistribution.set(provider, { total: 0, error: 0, warning: 0, info: 0 });
      }
      
      const entry = serviceDistribution.get(provider);
      entry.total++;
      
      const level = log.LevelDisplayName || '';
      if (level.includes('Error')) entry.error++;
      else if (level.includes('Warning')) entry.warning++;
      else entry.info++;
    });
    
    // Find error patterns (common error messages)
    const errorClusters = this.findErrorPatterns(logs.filter(log => {
      const level = log.LevelDisplayName || '';
      return level.includes('Error');
    }));
    
    return {
      summary: {
        total_logs: logs.length,
        error_count: levelCounts.error_count,
        warning_count: levelCounts.warning_count,
        anomaly_count: anomalies.length,
        cluster_count: clusters.length
      },
      time_series: timeSeries,
      service_distribution: Array.from(serviceDistribution.entries())
        .map(([name, stats]) => ({ name, ...stats }))
        .sort((a, b) => b.total - a.total),
      anomalies: anomalies.map(anomaly => ({
        ...anomaly,
        log: logs[anomaly.index]
      })),
      clusters,
      error_clusters: errorClusters,
      top_patterns: this.extractCommonTerms(logs.map(log => log.Message))
    };
  }
  
  /**
   * Detect anomalies in log data using Mahalanobis distance
   * @param {Matrix} dataMatrix - Matrix of feature vectors
   * @returns {Array} Detected anomalies
   */
  detectAnomalies(dataMatrix) {
    if (!this.baselineData.meanVector) {
      return [];
    }
    
    const anomalies = [];
    const { meanVector, covarianceMatrix, threshold } = this.baselineData;
    
    // Calculate inverse of covariance matrix (can be computationally expensive)
    let invCov;
    try {
      invCov = Matrix.inverse(new Matrix(covarianceMatrix));
    } catch (e) {
      // If matrix is singular, use pseudo-inverse or identity matrix
      console.log('Warning: Covariance matrix is singular, using identity matrix for anomaly detection');
      invCov = Matrix.eye(covarianceMatrix.length, covarianceMatrix.length);
    }
    
    // Calculate Mahalanobis distance for each sample
    for (let i = 0; i < dataMatrix.rows; i++) {
      const sampleVector = dataMatrix.getRow(i);
      const centeredVector = sampleVector.map((val, idx) => val - meanVector[idx]);
      
      // Calculate Mahalanobis distance: sqrt((x-μ)^T Σ^-1 (x-μ))
      const centeredMatrix = Matrix.columnVector(centeredVector);
      const mahalanobisDistance = Math.sqrt(
        centeredMatrix.transpose().mmul(invCov).mmul(centeredMatrix).get(0, 0)
      );
      
      if (mahalanobisDistance > threshold) {
        anomalies.push({
          index: i,
          score: mahalanobisDistance,
          type: 'statistical_outlier',
          description: `Unusual log entry pattern (anomaly score: ${mahalanobisDistance.toFixed(2)})`
        });
      }
    }
    
    return anomalies;
  }
  
  /**
   * Find common patterns in error messages
   * @param {Array} errorLogs - Array of error log entries
   * @returns {Array} Common error patterns
   */
  findErrorPatterns(errorLogs) {
    if (errorLogs.length === 0) {
      return [];
    }
    
    // Extract error messages
    const errorMessages = errorLogs.map(log => log.Message || '');
    
    // Group similar messages
    const patterns = new Map();
    
    for (let i = 0; i < errorMessages.length; i++) {
      const message = errorMessages[i];
      let matched = false;
      
      // Try to match with existing patterns
      for (const [pattern, data] of patterns.entries()) {
        if (this.areSimilarMessages(message, pattern)) {
          data.count++;
          if (data.examples.length < 3) {
            data.examples.push(message);
          }
          matched = true;
          break;
        }
      }
      
      // If no match, create a new pattern
      if (!matched) {
        patterns.set(message, {
          count: 1,
          examples: [message]
        });
      }
    }
    
    // Convert to array and sort by count
    return Array.from(patterns.entries())
      .map(([pattern, data]) => ({
        keywords: this.extractKeywords(pattern),
        count: data.count,
        examples: data.examples
      }))
      .filter(pattern => pattern.count > 1) // Only include patterns that occur multiple times
      .sort((a, b) => b.count - a.count)
      .slice(0, 10); // Return top 10 patterns
  }
  
  /**
   * Check if two messages are similar
   * @param {string} msg1 - First message
   * @param {string} msg2 - Second message
   * @returns {boolean} True if messages are similar
   */
  areSimilarMessages(msg1, msg2) {
    if (typeof msg1 !== 'string' || typeof msg2 !== 'string') {
      return false;
    }
    
    // Remove variable parts like timestamps, process IDs, and memory addresses
    const normalize = (str) => {
      return str
        .replace(/\d+/g, 'X') // Replace numbers
        .replace(/0x[0-9a-f]+/gi, 'ADDR') // Replace memory addresses
        .replace(/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}/gi, 'GUID') // Replace GUIDs
        .replace(/\\/g, '/') // Normalize path separators
        .toLowerCase();
    };
    
    const norm1 = normalize(msg1);
    const norm2 = normalize(msg2);
    
    // Calculate Levenshtein distance
    const distance = this.levenshteinDistance(norm1, norm2);
    const maxLength = Math.max(norm1.length, norm2.length);
    
    // Messages are similar if normalized edit distance is less than 30%
    return (distance / maxLength) < 0.3;
  }
  
  /**
   * Calculate Levenshtein distance between two strings
   * @param {string} s1 - First string
   * @param {string} s2 - Second string
   * @returns {number} Levenshtein distance
   */
  levenshteinDistance(s1, s2) {
    const m = s1.length;
    const n = s2.length;
    
    // Create matrix
    const d = Array(m + 1).fill().map(() => Array(n + 1).fill(0));
    
    // Initialize first row and column
    for (let i = 0; i <= m; i++) d[i][0] = i;
    for (let j = 0; j <= n; j++) d[0][j] = j;
    
    // Calculate distance
    for (let j = 1; j <= n; j++) {
      for (let i = 1; i <= m; i++) {
        const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
        d[i][j] = Math.min(
          d[i - 1][j] + 1,      // Deletion
          d[i][j - 1] + 1,      // Insertion
          d[i - 1][j - 1] + cost // Substitution
        );
      }
    }
    
    return d[m][n];
  }
  
  /**
   * Extract keywords from an error message
   * @param {string} message - Error message
   * @returns {string} Keywords from the message
   */
  extractKeywords(message) {
    if (typeof message !== 'string') {
      return '';
    }
    
    // Remove common variable parts
    const normalized = message
      .replace(/\d+/g, 'X')
      .replace(/0x[0-9a-f]+/gi, 'ADDR')
      .replace(/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}/gi, 'GUID');
    
    // Split into words and filter out common stopwords
    const stopwords = new Set(['the', 'a', 'an', 'in', 'on', 'at', 'by', 'for', 'with', 'about', 'is', 'was', 'to', 'from', 'and', 'or', 'but']);
    const words = normalized.split(/\s+/).filter(word => word.length > 3 && !stopwords.has(word.toLowerCase()));
    
    // Get most significant words (first 5-7 words or first 50 characters)
    if (words.length <= 7) {
      return words.join(' ');
    }
    
    const importantPart = words.slice(0, 7).join(' ');
    return importantPart.length > 50 ? importantPart.substring(0, 50) + '...' : importantPart;
  }
  
  /**
   * Extract common terms from a list of messages
   * @param {Array} messages - Array of messages
   * @returns {Array} Array of [term, count] pairs
   */
  extractCommonTerms(messages) {
    const wordCounts = new Map();
    const stopwords = new Set(['the', 'a', 'an', 'in', 'on', 'at', 'by', 'for', 'with', 'about', 'is', 'was', 'to', 'from', 'and', 'or', 'but', 'of', 'this', 'that', 'has', 'have', 'had', 'not', 'be', 'been', 'would', 'could', 'should']);
    
    // Count words
    messages.forEach(message => {
      if (typeof message !== 'string') return;
      
      const words = message.toLowerCase().split(/\W+/).filter(word => 
        word.length > 3 && !stopwords.has(word) && !/^\d+$/.test(word)
      );
      
      words.forEach(word => {
        wordCounts.set(word, (wordCounts.get(word) || 0) + 1);
      });
    });
    
    // Convert to array and sort by count
    return Array.from(wordCounts.entries())
      .filter(([_, count]) => count > 1) // Only include words that appear multiple times
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20); // Return top 20 terms
  }
}

/**
 * LogFeatureExtractor class - extracts numerical features from log entries
 */
class LogFeatureExtractor {
  constructor() {
    this.levelMap = {
      'Critical': 4,
      'Error': 3,
      'Warning': 2,
      'Information': 1,
      'Verbose': 0
    };
    
    this.providerCategories = {
      'System': 0,
      'Security': 1,
      'Application': 2,
      'Setup': 3,
      'PowerShell': 4
    };
  }
  
  /**
   * Extract numerical features from log entries
   * @param {Array} logs - Array of log entries
   * @returns {Array} Array of feature vectors
   */
  extractFeaturesFromLogs(logs) {
    if (!Array.isArray(logs) || logs.length === 0) {
      return [];
    }
    
    return logs.map(log => this.extractFeaturesFromLog(log));
  }
  
  /**
   * Extract numerical features from a single log entry
   * @param {Object} log - Log entry
   * @returns {Array} Feature vector
   */
  extractFeaturesFromLog(log) {
    if (!log) return Array(10).fill(0);
    
    // Extract basic numerical features
    const features = [];
    
    // 1. Log level (numeric)
    const levelText = log.LevelDisplayName || '';
    let level = 0;
    
    for (const [levelName, levelValue] of Object.entries(this.levelMap)) {
      if (levelText.includes(levelName)) {
        level = levelValue;
        break;
      }
    }
    features.push(level);
    
    // 2. Event ID (numeric value)
    features.push(log.Id || 0);
    
    // 3. Provider category (one-hot encoding)
    const provider = log.ProviderName || '';
    const providerFeatures = [0, 0, 0, 0, 0]; // One for each category
    
    for (const [categoryName, categoryIndex] of Object.entries(this.providerCategories)) {
      if (provider.includes(categoryName)) {
        providerFeatures[categoryIndex] = 1;
        break;
      }
    }
    features.push(...providerFeatures);
    
    // 4. Message length
    const message = log.Message || '';
    features.push(Math.min(message.length / 100, 10)); // Normalized length
    
    // 5. Time of day (hour, normalized to 0-1)
    let timeFeature = 0;
    try {
      const timestamp = new Date(log.TimeCreated);
      if (!isNaN(timestamp.getTime())) {
        timeFeature = timestamp.getHours() / 24;
      }
    } catch (e) {
      // Use default value if timestamp parsing fails
    }
    features.push(timeFeature);
    
    // 6. Has numbers in message
    features.push(/\d+/.test(message) ? 1 : 0);
    
    // 7. Has error keywords in message
    const errorKeywords = ['fail', 'error', 'exception', 'crash', 'invalid', 'denied', 'unable', 'cannot'];
    features.push(errorKeywords.some(keyword => message.toLowerCase().includes(keyword)) ? 1 : 0);
    
    return features;
  }
}

module.exports = { LogAnalyzer };
