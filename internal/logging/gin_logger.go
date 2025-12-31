package logging

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/gin-gonic/gin"
)

func GinLogrusLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := maskSensitiveQuery(c.Request.URL.RawQuery)

		c.Next()

		if raw != "" {
			path = path + "?" + raw
		}

		latency := time.Since(start)
		if latency > time.Minute {
			latency = latency.Truncate(time.Second)
		} else {
			latency = latency.Truncate(time.Millisecond)
		}

		statusCode := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method
		errorMessage := c.Errors.ByType(gin.ErrorTypePrivate).String()
		timestamp := time.Now().Format("2006/01/02 - 15:04:05")
		logLine := fmt.Sprintf("[GIN] %s | %3d | %13v | %15s | %-7s \"%s\"", timestamp, statusCode, latency, clientIP, method, path)
		if errorMessage != "" {
			logLine = logLine + " | " + errorMessage
		}

		switch {
		case statusCode >= http.StatusInternalServerError:
			Error(logLine)
		case statusCode >= http.StatusBadRequest:
			Warn(logLine)
		default:
			Info(logLine)
		}
	}
}

func GinLogrusRecovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered any) {
		WithFields(Fields{
			"panic": recovered,
			"stack": string(debug.Stack()),
			"path":  c.Request.URL.Path,
		}).Error("recovered from panic")

		c.AbortWithStatus(http.StatusInternalServerError)
	})
}
