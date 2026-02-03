package inference

import (
	"bufio"
	"fmt"
	"os"
	"runtime"

	ort "github.com/yalue/onnxruntime_go"
)

type Predictor struct {
	malwareSession *ort.DynamicAdvancedSession
	adwareSession  *ort.DynamicAdvancedSession
	featureOrder   []string
}

func InitONNX() error {
	// 1. Set path to the shared library
	// Arch Linux typically installs it here:
	ort.SetSharedLibraryPath("/usr/lib/libonnxruntime.so")
	
	// 2. Initialize Environment
	err := ort.InitializeEnvironment()
	if err != nil {
		return fmt.Errorf("failed to initialize onnx environment: %w", err)
	}
	return nil
}

func CleanupONNX() {
	ort.DestroyEnvironment()
}

func NewPredictor(modelDir string) (*Predictor, error) {

	p := &Predictor{}

	// 2. Load Feature Names
	file, err := os.Open(modelDir + "/feature_names.txt")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		p.featureOrder = append(p.featureOrder, scanner.Text())
	}

	// 3. Load Models using DynamicAdvancedSession
	// We only care about "output_label" (Index 0) to avoid ZipMap complexity with probabilities
	inputNames := []string{"float_input"}
	outputNames := []string{"output_label"}

	p.malwareSession, err = ort.NewDynamicAdvancedSession(
		modelDir+"/malware_classifier.onnx",
		inputNames,
		outputNames,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load malware model: %v", err)
	}

	p.adwareSession, err = ort.NewDynamicAdvancedSession(
		modelDir+"/adware_classifier.onnx",
		inputNames,
		outputNames,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load adware model: %v", err)
	}

	return p, nil
}

func (p *Predictor) Predict(features []float32) (isMalware bool, isAdware bool, err error) {
	
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// 1. Create Input Tensor
	inputShape := ort.NewShape(1, int64(len(features)))
	inputTensor, err := ort.NewTensor(inputShape, features)
	if err != nil {
		return false, false, fmt.Errorf("input tensor creation failed: %w", err)
	}

	defer inputTensor.Destroy()

	// 2. Create Output Tensors
	outputShape := ort.NewShape(1)
	
	// Malware Output Container
	malOutputTensor, err := ort.NewEmptyTensor[int64](outputShape)
	if err != nil {
		return false, false, fmt.Errorf("malware output tensor creation failed: %w", err)
	}
	defer malOutputTensor.Destroy()

	// Adware Output Container
	adOutputTensor, err := ort.NewEmptyTensor[int64](outputShape)
	if err != nil {
		return false, false, fmt.Errorf("adware output tensor creation failed: %w", err)
	}
	defer adOutputTensor.Destroy()

	// 3. Run Malware Model
	err = p.malwareSession.Run(
		[]ort.Value{inputTensor}, 
		[]ort.Value{malOutputTensor},
	)
	if err != nil {
		return false, false, fmt.Errorf("malware inference failed: %w", err)
	}

	// 4. Run Adware Model
	err = p.adwareSession.Run(
		[]ort.Value{inputTensor}, 
		[]ort.Value{adOutputTensor},
	)
	if err != nil {
		return false, false, fmt.Errorf("adware inference failed: %w", err)
	}

	// 5. Extract Data
	malLabels := malOutputTensor.GetData()
	adLabels := adOutputTensor.GetData()

	isMalware = malLabels[0] == 1
	isAdware = adLabels[0] == 1

	return isMalware, isAdware, nil
}

func (p *Predictor) GetFeatureOrder() []string {
	return p.featureOrder
}

func (p *Predictor) Close() {
	if p.malwareSession != nil {
		p.malwareSession.Destroy()
	}
	if p.adwareSession != nil {
		p.adwareSession.Destroy()
	}
}