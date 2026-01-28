#!/bin/bash

set -e  # Exit on any error

echo "=========================================="
echo "Setting up Network Listener Demo"
echo "=========================================="
echo ""

# Step 1: Create kind cluster
echo "Step 1: Creating kind cluster with port mappings..."
if kind get clusters | grep -q "^kind$"; then
    echo "Cluster 'kind' already exists. Deleting..."
    kind delete cluster
fi
kind create cluster --config kubernetes/kind-config.yaml
echo "✓ Cluster created"
echo ""

# Step 2: Build Docker image
echo "Step 2: Building Docker image (network:v3)..."
docker build -t network:v3 .
echo "✓ Image built"
echo ""

# Step 3: Load image into kind
echo "Step 3: Loading image into kind cluster..."
kind load docker-image network:v3
echo "✓ Image loaded"
echo ""

# Step 4: Deploy nginx
echo "Step 4: Deploying nginx..."
kubectl apply -f kubernetes/nginx-deployment.yaml
echo "✓ Nginx deployed"
echo ""

# Step 5: Deploy Spring app
echo "Step 5: Deploying Spring app..."
kubectl apply -f kubernetes/spring-app.yaml
echo "✓ Spring app deployed"
echo ""

# Step 6: Deploy packet sniffer
echo "Step 6: Deploying packet sniffer DaemonSet..."
kubectl apply -f kubernetes/daemonset.yaml
echo "✓ Packet sniffer deployed"
echo ""

# Step 7: Deploy curl pod
echo "Step 7: Deploying curl pod for testing..."
kubectl apply -f kubernetes/curl-deployment.yaml
echo "✓ Curl pod deployed"
echo ""

# Step 8: Wait for pods to be ready
echo "Step 8: Waiting for all pods to be ready..."
kubectl wait --for=condition=ready pod -l app=my-nginx --timeout=60s
kubectl wait --for=condition=ready pod -l app=spring-app --timeout=60s
kubectl wait --for=condition=ready pod -l name=packet-sniffer --timeout=60s
kubectl wait --for=condition=ready pod -l app=curl --timeout=60s
echo "✓ All pods ready"
echo ""

echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Test external traffic:"
echo "  Nginx:  curl http://localhost:32407"
echo "  Spring: curl http://localhost:30000"
echo ""
echo "Test pod-to-pod traffic:"
echo "  kubectl exec -l app=curl -- curl -s http://10.244.1.2"
echo "  kubectl exec -l app=curl -- curl -s http://spring-app.default.svc.cluster.local:3000"
echo ""
echo "View packet sniffer logs:"
echo "  kubectl logs -l name=packet-sniffer --follow"
echo ""
echo "View all pods:"
echo "  kubectl get pods -o wide"
echo ""
