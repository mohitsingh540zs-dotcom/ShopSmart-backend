import DataUriParser from "datauri/parser.js"
import path from "path"

const Parser = new DataUriParser();

const getDataUri = (file)=>{
    const extName = path.extname(file.originalname).toString();
    return Parser.format(extName, file.buffer).content;
};

export default getDataUri;