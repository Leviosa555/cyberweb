const express = require('express');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const SecurityEngineManager = require('../services/securityEngines');
const router = express.Router();

const securityManager = new SecurityEngineManager();

router.post('/analyze', 
    [
        body('url')
            .isURL({ protocols: ['http', 'https'], require_protocol: true })
            .withMessage('Valid URL with protocol required')
            .isLength({ max: 2048 })
            .withMessage('URL too long')
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const { url, options = {} } = req.body;
            const startTime = Date.now();

            const results = await securityManager.scanURL(url, options);
            
            results.metadata = {
                scanId: crypto.randomUUID(),
                timestamp: new Date().toISOString(),
                processingTime: Date.now() - startTime,
                version: '1.0.0'
            };

            res.json({
                success: true,
                data: results
            });

        } catch (error) {
            console.error('Analysis error:', error);
            res.status(500).json({
                success: false,
                error: 'Analysis failed',
                message: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
            });
        }
    }
);

module.exports = router;
