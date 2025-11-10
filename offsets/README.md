## Offset list format
The offset list is a json object where each key corresponds to the hash value of a tracking resource, and for each tracking resource we have the attributes "num" and "parts".
<br>
- num [int]: Indicates the number of tracking ASTs (or parts) to remove from the original resource. If the value equals -1, it means that the resource must be fully removed (e.g. returning empty string).
- parts [list]: Contains a list of tuples size 2, where the first element is the offset from the start of the original resource, and the second element is the length of bytes we need to remove from that offset. 
<br>
Format type sample:
```
"hash": {
    "num": int,
    "parts": [(offset0, length0), (offset1, length1), ..., (offsetN, lengthN)]
}
```
<br>
Offset list sample:
```
{
    "e4f48e1f5558252eba1d25be60a35a35a024390cf4970e0652b9e654f9e0302b": {
        "num": 3,
        "parts": [[1057, 409], [1568, 1277], [3779, 495]]
    },
    "efba4cf25710ca282dd469d9cbc0adc0cdebfbe5c40402d56f24def7df7b2a38": {
        "num": 1,
        "parts": [[0, 3546]]
    },
    "9902b2f28c7a76bf318ed2792209816447376e07d7f765709d38739332293948": {
        "num": -1,
        "parts": []
    }
}
```
