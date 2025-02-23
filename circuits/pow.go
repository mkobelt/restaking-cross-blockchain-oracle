package restaking

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

func Pow(api frontend.API, x frontend.Variable, y frontend.Variable) frontend.Variable {
	output := frontend.Variable(1)
	b := bits.ToBinary(api, y, bits.WithNbDigits(256))

	for i := range b {
		if i != 0 {
			output = api.Mul(output, output)
		}
		multiply := api.Mul(output, x)
		output = api.Select(b[len(b)-1-i], multiply, output)
	}

	return output
}
