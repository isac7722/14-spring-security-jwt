package coml.ohgiraffers.security.common.utils;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class ConvertUtil {
    public static Object convertObjectToJsonObject(Object object){
        ObjectMapper mapper = new ObjectMapper();
        JSONParser parser = new JSONParser();
        String convertJsonString;
        Object convertObj;

        try {
            convertJsonString = mapper.writeValueAsString(object);
            convertObj = parser.parse(convertJsonString);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }

        return convertObj;
    }

}
