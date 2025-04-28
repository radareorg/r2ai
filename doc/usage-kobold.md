# Using kobold-ai from r2ai

KoboldCpp is a fork of llamacpp that exposes a server that r2ai can comuniate with to send queries. One of the main benefits is that it can handle large inputs on a variety of models and it's quite fast.


## Installation

```
r2pm -ci koboldcpp
```

## Running

Start your browser and do your things

```
koboldcpp --model /path/to/gguf
```

Then connect r2ai to it using the koboldcpp model:

```
r2ai '-m koboldcpp'
```

which defaults to:

```
r2ai '-m koboldcpp:http://localhost:5001'
```
