#!/bin/bash
"""
Build and deployment script for malware detection API
For MLSEC competition submission
"""

# Configuration
IMAGE_NAME="malware-detector"
CONTAINER_NAME="malware-detector-container"
PORT=8080

echo "============================================"
echo "Malware Detection API - Competition Builder"
echo "============================================"

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        echo "❌ Docker is not running. Please start Docker first."
        exit 1
    fi
    echo "✅ Docker is running"
}

# Function to build the Docker image
build_image() {
    echo ""
    echo "📦 Building Docker image..."
    echo "Building: $IMAGE_NAME"
    
    # Build the image
    docker build -t $IMAGE_NAME . --no-cache
    
    if [ $? -eq 0 ]; then
        echo "✅ Docker image built successfully"
        
        # Check image size
        size=$(docker images $IMAGE_NAME --format "table {{.Size}}" | tail -n 1)
        echo "📏 Image size: $size"
        
        # Check if size is reasonable (should be < 1GB uncompressed)
        echo "⚠️  Make sure the uncompressed size is < 1GB for competition"
    else
        echo "❌ Docker build failed"
        exit 1
    fi
}

# Function to run the container
run_container() {
    echo ""
    echo "🚀 Starting Docker container..."
    
    # Stop existing container if running
    docker stop $CONTAINER_NAME 2>/dev/null
    docker rm $CONTAINER_NAME 2>/dev/null
    
    # Run the container with competition constraints
    docker run -d \
        --name $CONTAINER_NAME \
        -p $PORT:8080 \
        --memory=1.5g \
        --cpus=1 \
        $IMAGE_NAME
    
    if [ $? -eq 0 ]; then
        echo "✅ Container started successfully"
        echo "🌐 API available at: http://localhost:$PORT"
        echo ""
        echo "Container info:"
        docker ps | grep $CONTAINER_NAME
    else
        echo "❌ Failed to start container"
        exit 1
    fi
}

# Function to test the API
test_api() {
    echo ""
    echo "🧪 Testing API..."
    
    # Wait for container to be ready
    echo "Waiting for API to be ready..."
    sleep 10
    
    # Run the test script
    if [ -f "test_api.py" ]; then
        python3 test_api.py
    else
        echo "test_api.py not found, running basic health check..."
        curl -f http://localhost:$PORT/health || echo "Health check failed"
    fi
}

# Function to save image for competition
save_image() {
    echo ""
    echo "💾 Saving Docker image for competition submission..."
    
    # Save the image
    docker save -o ${IMAGE_NAME}.tar $IMAGE_NAME
    
    if [ $? -eq 0 ]; then
        echo "✅ Image saved as ${IMAGE_NAME}.tar"
        
        # Get file size
        size=$(ls -lh ${IMAGE_NAME}.tar | awk '{print $5}')
        echo "📏 Saved image size: $size"
        
        # Compress with gzip
        echo "🗜️  Compressing with gzip..."
        gzip ${IMAGE_NAME}.tar
        
        compressed_size=$(ls -lh ${IMAGE_NAME}.tar.gz | awk '{print $5}')
        echo "✅ Compressed image: ${IMAGE_NAME}.tar.gz ($compressed_size)"
        echo ""
        echo "📤 Ready for competition upload!"
        echo "Upload file: ${IMAGE_NAME}.tar.gz"
    else
        echo "❌ Failed to save image"
        exit 1
    fi
}

# Function to view logs
view_logs() {
    echo ""
    echo "📋 Container logs:"
    docker logs $CONTAINER_NAME
}

# Function to stop container
stop_container() {
    echo ""
    echo "🛑 Stopping container..."
    docker stop $CONTAINER_NAME
    docker rm $CONTAINER_NAME
    echo "✅ Container stopped and removed"
}

# Function to show help
show_help() {
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  build     - Build the Docker image"
    echo "  run       - Run the container"
    echo "  test      - Test the API"
    echo "  save      - Save image for competition"
    echo "  logs      - View container logs"
    echo "  stop      - Stop and remove container"
    echo "  all       - Build, run, and test (default)"
    echo "  help      - Show this help"
    echo ""
}

# Main script logic
case "${1:-all}" in
    "build")
        check_docker
        build_image
        ;;
    "run")
        check_docker
        run_container
        ;;
    "test")
        test_api
        ;;
    "save")
        check_docker
        save_image
        ;;
    "logs")
        view_logs
        ;;
    "stop")
        stop_container
        ;;
    "all")
        check_docker
        build_image
        run_container
        test_api
        ;;
    "help"|"-h"|"--help")
        show_help
        ;;
    *)
        echo "❌ Unknown command: $1"
        show_help
        exit 1
        ;;
esac

echo ""
echo "🏁 Script completed!"
