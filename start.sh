echo "Running detect.py..."
python3 detect.py && \
echo "detect.py done, running evaluate.py..." && \
python3 evaluate.py && \
echo "All tasks completed successfully!"